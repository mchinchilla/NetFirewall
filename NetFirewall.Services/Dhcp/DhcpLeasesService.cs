using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Dhcp;
using Npgsql;
using RepoDb;

namespace NetFirewall.Services.Dhcp;

/// <summary>
/// High-performance DHCP leases service with in-memory cache and DDNS support.
/// Cache provides O(1) lookups, write-through to PostgreSQL for durability.
/// </summary>
public sealed class DhcpLeasesService : IDhcpLeasesService
{
    private readonly ILogger<DhcpLeasesService> _logger;
    private readonly NpgsqlDataSource _dataSource;
    private readonly IDdnsService? _ddnsService;
    private readonly LeaseCache? _leaseCache;

    // Thread-safe cache for parsed MAC addresses - no locks needed
    private static readonly ConcurrentDictionary<string, PhysicalAddress> MacCache = new(StringComparer.OrdinalIgnoreCase);

    public DhcpLeasesService(
        NpgsqlDataSource dataSource,
        ILogger<DhcpLeasesService> logger,
        LeaseCache? leaseCache = null,
        IDdnsService? ddnsService = null)
    {
        _logger = logger;
        _dataSource = dataSource;
        _leaseCache = leaseCache;
        _ddnsService = ddnsService;
    }

    /// <summary>
    /// Check if lease cache is available and warmed up.
    /// </summary>
    public bool IsCacheEnabled => _leaseCache != null;

    /// <summary>
    /// Get cache statistics for monitoring.
    /// </summary>
    public LeaseCacheStats? GetCacheStats() => _leaseCache?.GetStats();

    public async Task<IPAddress?> OfferLeaseAsync(string macAddress, IPAddress? rangeStart, IPAddress rangeEnd)
    {
        // FAST PATH: Check cache first (O(1) lookup)
        if (_leaseCache != null)
        {
            // Check for existing lease in cache
            var cachedLease = _leaseCache.GetByMac(macAddress);
            if (cachedLease != null)
            {
                return cachedLease.IpAddress;
            }

            // Find available IP from cache (no DB hit)
            var availableIp = _leaseCache.FindAvailableIp(rangeStart!, rangeEnd);
            if (availableIp != null)
            {
                return availableIp;
            }

            // Cache miss for available IP - fall through to DB
            // This should be rare after warmup
        }

        // SLOW PATH: Database lookup (fallback)
        await using var connection = await _dataSource.OpenConnectionAsync().ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync().ConfigureAwait(false);

        try
        {
            // First check for MAC reservation (single query)
            var reservedIp = await GetReservationInternalAsync(connection, macAddress, transaction).ConfigureAwait(false);
            if (reservedIp != null)
            {
                await transaction.CommitAsync().ConfigureAwait(false);
                return reservedIp;
            }

            // Check for existing lease for this MAC
            var existingIp = await GetExistingLeaseIpAsync(connection, macAddress, transaction).ConfigureAwait(false);
            if (existingIp != null)
            {
                await transaction.CommitAsync().ConfigureAwait(false);
                return existingIp;
            }

            // Find first available IP using optimized SQL
            var availableIp = await FindAvailableIpAsync(
                connection,
                rangeStart!.ToString(),
                rangeEnd.ToString(),
                transaction
            ).ConfigureAwait(false);

            await transaction.CommitAsync().ConfigureAwait(false);
            return availableIp;
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync().ConfigureAwait(false);
            _logger.LogError(ex, "Error offering lease for MAC {Mac}", macAddress);
            return null;
        }
    }

    private async Task<IPAddress?> GetExistingLeaseIpAsync(
        NpgsqlConnection connection,
        string macAddress,
        NpgsqlTransaction transaction)
    {
        var parsedMac = ParseMacAddress(macAddress);
        var now = DateTime.UtcNow;

        // Use raw SQL for better performance
        const string sql = @"
            SELECT ip_address
            FROM dhcp_leases
            WHERE mac_address = @mac AND end_time > @now
            LIMIT 1";

        await using var cmd = new NpgsqlCommand(sql, connection, transaction);
        cmd.Parameters.AddWithValue("mac", parsedMac);
        cmd.Parameters.AddWithValue("now", now);

        var result = await cmd.ExecuteScalarAsync().ConfigureAwait(false);
        return result as IPAddress;
    }

    private async Task<IPAddress?> FindAvailableIpAsync(
        NpgsqlConnection connection,
        string rangeStart,
        string rangeEnd,
        NpgsqlTransaction transaction)
    {
        // Optimized query using generate_series with proper locking
        const string sql = @"
            WITH ip_series AS (
                SELECT ip::inet AS ip
                FROM generate_series(1,
                    (inet @rangeEnd - inet @rangeStart + 1)::int
                ) AS idx,
                LATERAL (SELECT (inet @rangeStart + idx - 1) AS ip) AS computed
            ),
            used_ips AS (
                SELECT ip_address FROM dhcp_leases WHERE end_time > @now
                UNION ALL
                SELECT reserved_ip FROM dhcp_mac_reservations
            )
            SELECT ip FROM ip_series
            WHERE ip NOT IN (SELECT ip_address FROM used_ips WHERE ip_address IS NOT NULL)
            LIMIT 1
            FOR UPDATE SKIP LOCKED";

        try
        {
            await using var cmd = new NpgsqlCommand(sql, connection, transaction);
            cmd.Parameters.AddWithValue("rangeStart", rangeStart);
            cmd.Parameters.AddWithValue("rangeEnd", rangeEnd);
            cmd.Parameters.AddWithValue("now", DateTime.UtcNow);

            var result = await cmd.ExecuteScalarAsync().ConfigureAwait(false);
            return result as IPAddress;
        }
        catch (PostgresException)
        {
            // Fallback to simpler iteration if generate_series fails
            return await FindAvailableIpFallbackAsync(connection, rangeStart, rangeEnd, transaction).ConfigureAwait(false);
        }
    }

    private async Task<IPAddress?> FindAvailableIpFallbackAsync(
        NpgsqlConnection connection,
        string rangeStart,
        string rangeEnd,
        NpgsqlTransaction transaction)
    {
        var startIp = IPAddress.Parse(rangeStart);
        var endIp = IPAddress.Parse(rangeEnd);
        var now = DateTime.UtcNow;

        for (var ip = startIp; CompareIpAddresses(ip, endIp) <= 0; ip = IncrementIpAddress(ip)!)
        {
            // Check if IP is available
            const string checkSql = @"
                SELECT 1 FROM dhcp_leases WHERE ip_address = @ip AND end_time > @now
                UNION ALL
                SELECT 1 FROM dhcp_mac_reservations WHERE reserved_ip = @ip
                LIMIT 1";

            await using var cmd = new NpgsqlCommand(checkSql, connection, transaction);
            cmd.Parameters.AddWithValue("ip", ip);
            cmd.Parameters.AddWithValue("now", now);

            var exists = await cmd.ExecuteScalarAsync().ConfigureAwait(false);
            if (exists == null)
            {
                return ip;
            }
        }

        return null;
    }

    public async Task AssignLeaseAsync(string macAddress, IPAddress ipAddress, int leaseTime)
    {
        // FAST PATH: Use cache with async write-through
        if (_leaseCache != null)
        {
            await _leaseCache.SetLeaseAsync(macAddress, ipAddress, leaseTime).ConfigureAwait(false);

            if (_logger.IsEnabled(LogLevel.Debug))
            {
                _logger.LogDebug("Assigned {Ip} to {Mac} for {Lease}s (cached)", ipAddress, macAddress, leaseTime);
            }
            return;
        }

        // SLOW PATH: Direct database write
        await using var connection = await _dataSource.OpenConnectionAsync().ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync().ConfigureAwait(false);

        try
        {
            var parsedMac = ParseMacAddress(macAddress);
            var now = DateTime.UtcNow;
            var endTime = now.AddSeconds(leaseTime);

            // Upsert in single query
            const string sql = @"
                INSERT INTO dhcp_leases (id, mac_address, ip_address, start_time, end_time)
                VALUES (@id, @mac, @ip, @start, @end)
                ON CONFLICT (mac_address)
                DO UPDATE SET ip_address = @ip, start_time = @start, end_time = @end";

            await using var cmd = new NpgsqlCommand(sql, connection, transaction);
            cmd.Parameters.AddWithValue("id", Guid.NewGuid());
            cmd.Parameters.AddWithValue("mac", parsedMac);
            cmd.Parameters.AddWithValue("ip", ipAddress);
            cmd.Parameters.AddWithValue("start", now);
            cmd.Parameters.AddWithValue("end", endTime);

            await cmd.ExecuteNonQueryAsync().ConfigureAwait(false);
            await transaction.CommitAsync().ConfigureAwait(false);

            if (_logger.IsEnabled(LogLevel.Debug))
            {
                _logger.LogDebug("Assigned {Ip} to {Mac} for {Lease}s", ipAddress, macAddress, leaseTime);
            }
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync().ConfigureAwait(false);
            _logger.LogError(ex, "Error assigning {Ip} to {Mac}", ipAddress, macAddress);
        }
    }

    public async Task<bool> CanAssignIpAsync(string macAddress, IPAddress ipAddress)
    {
        // FAST PATH: Check cache first (O(1))
        if (_leaseCache != null)
        {
            return _leaseCache.CanMacUseIp(macAddress, ipAddress);
        }

        // SLOW PATH: Database check
        await using var connection = await _dataSource.OpenConnectionAsync().ConfigureAwait(false);

        try
        {
            // Check reservation first
            var reservedIp = await GetReservationInternalAsync(connection, macAddress, null).ConfigureAwait(false);
            if (reservedIp != null)
            {
                return reservedIp.Equals(ipAddress);
            }

            var parsedMac = ParseMacAddress(macAddress);
            var now = DateTime.UtcNow;

            // Check if IP is available or already assigned to this MAC
            const string sql = @"
                SELECT mac_address FROM dhcp_leases
                WHERE ip_address = @ip AND end_time > @now
                LIMIT 1";

            await using var cmd = new NpgsqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("ip", ipAddress);
            cmd.Parameters.AddWithValue("now", now);

            var result = await cmd.ExecuteScalarAsync().ConfigureAwait(false);
            if (result == null)
            {
                return true; // IP is free
            }

            // Check if lease belongs to this MAC
            return result is PhysicalAddress existingMac && existingMac.Equals(parsedMac);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking if {Ip} can be assigned to {Mac}", ipAddress, macAddress);
            return false;
        }
    }

    public async Task ReleaseLeaseAsync(string macAddress)
    {
        // FAST PATH: Use cache with async write-through
        if (_leaseCache != null)
        {
            await _leaseCache.ReleaseLeaseAsync(macAddress).ConfigureAwait(false);

            if (_logger.IsEnabled(LogLevel.Debug))
            {
                _logger.LogDebug("Released lease for {Mac} (cached)", macAddress);
            }
            return;
        }

        // SLOW PATH: Direct database delete
        await using var connection = await _dataSource.OpenConnectionAsync().ConfigureAwait(false);

        try
        {
            var parsedMac = ParseMacAddress(macAddress);

            const string sql = "DELETE FROM dhcp_leases WHERE mac_address = @mac";
            await using var cmd = new NpgsqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("mac", parsedMac);

            await cmd.ExecuteNonQueryAsync().ConfigureAwait(false);

            if (_logger.IsEnabled(LogLevel.Debug))
            {
                _logger.LogDebug("Released lease for {Mac}", macAddress);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error releasing lease for {Mac}", macAddress);
        }
    }

    public async Task<IPAddress?> CheckForReservationAsync(string macAddress)
    {
        await using var connection = await _dataSource.OpenConnectionAsync().ConfigureAwait(false);
        return await GetReservationInternalAsync(connection, macAddress, null).ConfigureAwait(false);
    }

    private async Task<IPAddress?> GetReservationInternalAsync(
        NpgsqlConnection connection,
        string macAddress,
        NpgsqlTransaction? transaction)
    {
        try
        {
            var parsedMac = ParseMacAddress(macAddress);

            const string sql = "SELECT reserved_ip FROM dhcp_mac_reservations WHERE mac_address = @mac LIMIT 1";
            await using var cmd = new NpgsqlCommand(sql, connection, transaction);
            cmd.Parameters.AddWithValue("mac", parsedMac);

            var result = await cmd.ExecuteScalarAsync().ConfigureAwait(false);
            return result as IPAddress;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking reservation for {Mac}", macAddress);
            return null;
        }
    }

    public async Task MarkIpAsDeclinedAsync(IPAddress ipAddress)
    {
        await using var connection = await _dataSource.OpenConnectionAsync().ConfigureAwait(false);

        try
        {
            const string sql = "DELETE FROM dhcp_leases WHERE ip_address = @ip";
            await using var cmd = new NpgsqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("ip", ipAddress);

            await cmd.ExecuteNonQueryAsync().ConfigureAwait(false);

            if (_logger.IsEnabled(LogLevel.Debug))
            {
                _logger.LogDebug("Marked {Ip} as declined", ipAddress);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error marking {Ip} as declined", ipAddress);
        }
    }

    public async Task<IPAddress?> GetAssignedIpAsync(string macAddress)
    {
        // FAST PATH: Check cache first (O(1))
        if (_leaseCache != null)
        {
            var cached = _leaseCache.GetByMac(macAddress);
            if (cached != null)
            {
                return cached.IpAddress;
            }
            return null; // Not in cache = no active lease
        }

        // SLOW PATH: Database lookup
        await using var connection = await _dataSource.OpenConnectionAsync().ConfigureAwait(false);

        try
        {
            var parsedMac = ParseMacAddress(macAddress);
            var now = DateTime.UtcNow;

            const string sql = @"
                SELECT ip_address FROM dhcp_leases
                WHERE mac_address = @mac AND end_time > @now
                LIMIT 1";

            await using var cmd = new NpgsqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("mac", parsedMac);
            cmd.Parameters.AddWithValue("now", now);

            var result = await cmd.ExecuteScalarAsync().ConfigureAwait(false);
            return result as IPAddress;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting assigned IP for {Mac}", macAddress);
            return null;
        }
    }

    /// <summary>
    /// Parse MAC address with thread-safe caching to avoid repeated parsing.
    /// Uses ConcurrentDictionary for lock-free access.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static PhysicalAddress ParseMacAddress(string macAddress)
    {
        // Normalize format: AA:BB:CC:DD:EE:FF -> AA-BB-CC-DD-EE-FF
        var normalized = macAddress.Replace(":", "-").ToUpperInvariant();

        // GetOrAdd is atomic and thread-safe
        return MacCache.GetOrAdd(normalized, static key =>
        {
            // Limit cache size to prevent unbounded memory growth
            // Note: This check is approximate due to concurrency, but acceptable
            if (MacCache.Count >= 10000)
            {
                // Clear oldest entries (simple eviction strategy)
                MacCache.Clear();
            }

            return PhysicalAddress.Parse(key);
        });
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static IPAddress? IncrementIpAddress(IPAddress? ip)
    {
        if (ip == null) return null;

        Span<byte> bytes = stackalloc byte[4];
        ip.TryWriteBytes(bytes, out _);

        for (int i = 3; i >= 0; i--)
        {
            if (++bytes[i] != 0)
            {
                return new IPAddress(bytes);
            }
        }

        return null; // Overflow
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int CompareIpAddresses(IPAddress? ip1, IPAddress? ip2)
    {
        if (ip1 == null || ip2 == null) return 0;

        Span<byte> bytes1 = stackalloc byte[4];
        Span<byte> bytes2 = stackalloc byte[4];

        ip1.TryWriteBytes(bytes1, out _);
        ip2.TryWriteBytes(bytes2, out _);

        for (int i = 0; i < 4; i++)
        {
            int cmp = bytes1[i].CompareTo(bytes2[i]);
            if (cmp != 0) return cmp;
        }

        return 0;
    }

    #region Bulk Operations (using PostgreSQL COPY protocol)

    /// <summary>
    /// Bulk import MAC reservations using PostgreSQL binary COPY protocol.
    /// This is extremely efficient for large datasets (10x-100x faster than individual inserts).
    /// </summary>
    public async Task<int> BulkImportReservationsAsync(
        IEnumerable<DhcpMacReservation> reservations,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            var reservationList = reservations as IList<DhcpMacReservation> ?? reservations.ToList();

            if (reservationList.Count == 0)
            {
                return 0;
            }

            // Ensure all have IDs
            foreach (var reservation in reservationList)
            {
                if (reservation.Id == Guid.Empty)
                {
                    reservation.Id = Guid.NewGuid();
                }
            }

            // Use RepoDb BinaryBulkInsert for PostgreSQL COPY protocol
            var inserted = await connection.BinaryBulkInsertAsync(
                tableName: "dhcp_mac_reservations",
                entities: reservationList,
                cancellationToken: cancellationToken
            ).ConfigureAwait(false);

            _logger.LogInformation("Bulk imported {Count} MAC reservations", inserted);
            return inserted;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error bulk importing reservations");
            throw;
        }
    }

    /// <summary>
    /// Bulk import DHCP leases using PostgreSQL binary COPY protocol.
    /// Useful for migrating leases from another DHCP server or restoring from backup.
    /// </summary>
    public async Task<int> BulkImportLeasesAsync(
        IEnumerable<DhcpLease> leases,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            var leaseList = leases as IList<DhcpLease> ?? leases.ToList();

            if (leaseList.Count == 0)
            {
                return 0;
            }

            // Ensure all have IDs
            foreach (var lease in leaseList)
            {
                if (lease.Id == Guid.Empty)
                {
                    lease.Id = Guid.NewGuid();
                }
            }

            // Use RepoDb BinaryBulkInsert for PostgreSQL COPY protocol
            var inserted = await connection.BinaryBulkInsertAsync(
                tableName: "dhcp_leases",
                entities: leaseList,
                cancellationToken: cancellationToken
            ).ConfigureAwait(false);

            _logger.LogInformation("Bulk imported {Count} DHCP leases", inserted);
            return inserted;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error bulk importing leases");
            throw;
        }
    }

    #endregion

    #region Maintenance Operations

    /// <summary>
    /// Remove all expired leases from the database.
    /// Should be called periodically (e.g., every hour) to keep the table clean.
    /// </summary>
    public async Task<int> CleanupExpiredLeasesAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            const string sql = "DELETE FROM dhcp_leases WHERE end_time < @now";
            await using var cmd = new NpgsqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("now", DateTime.UtcNow);

            var deleted = await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

            if (deleted > 0)
            {
                _logger.LogInformation("Cleaned up {Count} expired DHCP leases", deleted);
            }

            return deleted;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error cleaning up expired leases");
            throw;
        }
    }

    /// <summary>
    /// Get all active (non-expired) leases.
    /// </summary>
    public async Task<IReadOnlyList<DhcpLease>> GetAllActiveLeasesAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            var now = DateTime.UtcNow;

            // Use raw SQL for complex WHERE clause
            const string sql = @"
                SELECT id, mac_address, ip_address, hostname, start_time, end_time
                FROM dhcp_leases
                WHERE end_time > @now
                ORDER BY start_time DESC";

            await using var cmd = new NpgsqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("now", now);

            var leases = new List<DhcpLease>();
            await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                leases.Add(new DhcpLease
                {
                    Id = reader.GetGuid(0),
                    MacAddress = (PhysicalAddress)reader.GetValue(1),
                    IpAddress = (IPAddress)reader.GetValue(2),
                    Hostname = reader.IsDBNull(3) ? null : reader.GetString(3),
                    StartTime = reader.GetDateTime(4),
                    EndTime = reader.GetDateTime(5)
                });
            }

            return leases;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting active leases");
            throw;
        }
    }

    /// <summary>
    /// Get all MAC reservations.
    /// </summary>
    public async Task<IReadOnlyList<DhcpMacReservation>> GetAllReservationsAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            const string sql = @"
                SELECT id, mac_address, ip_address
                FROM dhcp_mac_reservations
                ORDER BY ip_address";

            await using var cmd = new NpgsqlCommand(sql, connection);

            var reservations = new List<DhcpMacReservation>();
            await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                reservations.Add(new DhcpMacReservation
                {
                    Id = reader.GetGuid(0),
                    MacAddress = (PhysicalAddress)reader.GetValue(1),
                    ReservedIp = (IPAddress)reader.GetValue(2)
                });
            }

            return reservations;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error getting reservations");
            throw;
        }
    }

    #endregion

    #region DDNS-Enabled Operations

    public async Task<DdnsUpdateResult?> AssignLeaseWithDdnsAsync(
        string macAddress,
        IPAddress ipAddress,
        int leaseTime,
        string? hostname,
        Guid? subnetId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            var parsedMac = ParseMacAddress(macAddress);
            var now = DateTime.UtcNow;
            var endTime = now.AddSeconds(leaseTime);

            // Upsert lease with hostname and FQDN
            const string sql = @"
                INSERT INTO dhcp_leases (id, mac_address, ip_address, hostname, start_time, end_time)
                VALUES (@id, @mac, @ip, @hostname, @start, @end)
                ON CONFLICT (mac_address)
                DO UPDATE SET ip_address = @ip, hostname = @hostname, start_time = @start, end_time = @end
                RETURNING id";

            await using var cmd = new NpgsqlCommand(sql, connection, transaction);
            var leaseId = Guid.NewGuid();
            cmd.Parameters.AddWithValue("id", leaseId);
            cmd.Parameters.AddWithValue("mac", parsedMac);
            cmd.Parameters.AddWithValue("ip", ipAddress);
            cmd.Parameters.AddWithValue("hostname", hostname ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("start", now);
            cmd.Parameters.AddWithValue("end", endTime);

            var result = await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            if (result != null)
            {
                leaseId = (Guid)result;
            }

            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);

            // Perform DDNS update if service is available and hostname is provided
            DdnsUpdateResult? ddnsResult = null;
            if (_ddnsService != null && !string.IsNullOrEmpty(hostname))
            {
                var ddnsConfig = await _ddnsService.GetConfigForSubnetAsync(subnetId, cancellationToken)
                    .ConfigureAwait(false);

                if (ddnsConfig != null && ddnsConfig.Enabled)
                {
                    ddnsResult = await _ddnsService.UpdateLeaseRecordsAsync(
                        hostname, ipAddress, macAddress, ddnsConfig, cancellationToken).ConfigureAwait(false);

                    // Log DDNS result
                    await LogDdnsUpdateAsync(connection, leaseId, hostname, ipAddress, ddnsResult, ddnsConfig, cancellationToken)
                        .ConfigureAwait(false);
                }
            }

            if (_logger.IsEnabled(LogLevel.Debug))
            {
                _logger.LogDebug("Assigned {Ip} to {Mac} (hostname={Hostname}) for {Lease}s",
                    ipAddress, macAddress, hostname, leaseTime);
            }

            return ddnsResult;
        }
        catch (Exception ex)
        {
            await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
            _logger.LogError(ex, "Error assigning {Ip} to {Mac} with DDNS", ipAddress, macAddress);
            return null;
        }
    }

    public async Task<DdnsUpdateResult?> ReleaseLeaseWithDdnsAsync(
        string macAddress,
        Guid? subnetId,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            // Get lease info before deleting for DDNS cleanup
            var (lease, _) = await GetLeaseInfoAsync(connection, macAddress, cancellationToken).ConfigureAwait(false);

            if (lease == null)
            {
                return null;
            }

            // Delete the lease
            const string deleteSql = "DELETE FROM dhcp_leases WHERE mac_address = @mac";
            await using var deleteCmd = new NpgsqlCommand(deleteSql, connection);
            deleteCmd.Parameters.AddWithValue("mac", ParseMacAddress(macAddress));
            await deleteCmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

            // Perform DDNS cleanup if service is available and hostname was registered
            DdnsUpdateResult? ddnsResult = null;
            if (_ddnsService != null && !string.IsNullOrEmpty(lease.Hostname))
            {
                var ddnsConfig = await _ddnsService.GetConfigForSubnetAsync(subnetId, cancellationToken)
                    .ConfigureAwait(false);

                if (ddnsConfig != null && ddnsConfig.Enabled)
                {
                    ddnsResult = await _ddnsService.RemoveLeaseRecordsAsync(
                        lease.Hostname, lease.IpAddress, ddnsConfig, cancellationToken).ConfigureAwait(false);

                    // Log DDNS removal
                    await LogDdnsRemovalAsync(connection, lease.Id, lease.Hostname, lease.IpAddress, ddnsResult, ddnsConfig, cancellationToken)
                        .ConfigureAwait(false);
                }
            }

            _logger.LogInformation("Released lease for {Mac} (hostname={Hostname})", macAddress, lease.Hostname);
            return ddnsResult;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error releasing lease with DDNS for {Mac}", macAddress);
            return null;
        }
    }

    public async Task<(DhcpLease? Lease, string? Fqdn)> GetLeaseWithFqdnAsync(
        string macAddress,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);
        return await GetLeaseInfoAsync(connection, macAddress, cancellationToken).ConfigureAwait(false);
    }

    private async Task<(DhcpLease? Lease, string? Fqdn)> GetLeaseInfoAsync(
        NpgsqlConnection connection,
        string macAddress,
        CancellationToken cancellationToken)
    {
        var parsedMac = ParseMacAddress(macAddress);

        const string sql = @"
            SELECT id, mac_address, ip_address, hostname, start_time, end_time
            FROM dhcp_leases
            WHERE mac_address = @mac";

        await using var cmd = new NpgsqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("mac", parsedMac);

        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

        if (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var lease = new DhcpLease
            {
                Id = reader.GetGuid(0),
                MacAddress = (PhysicalAddress)reader.GetValue(1),
                IpAddress = (IPAddress)reader.GetValue(2),
                Hostname = reader.IsDBNull(3) ? null : reader.GetString(3),
                StartTime = reader.GetDateTime(4),
                EndTime = reader.GetDateTime(5)
            };

            // FQDN would be stored if we had a separate column, for now just return hostname
            return (lease, lease.Hostname);
        }

        return (null, null);
    }

    private async Task LogDdnsUpdateAsync(
        NpgsqlConnection connection,
        Guid leaseId,
        string hostname,
        IPAddress ipAddress,
        DdnsUpdateResult result,
        DdnsConfig config,
        CancellationToken cancellationToken)
    {
        try
        {
            if (result.ForwardSuccess || !string.IsNullOrEmpty(result.ForwardError))
            {
                await InsertDdnsLogAsync(connection, leaseId, "add_forward", hostname, ipAddress,
                    result.Fqdn, result.ForwardSuccess, result.ForwardError, config.DnsServer, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (result.ReverseSuccess || !string.IsNullOrEmpty(result.ReverseError))
            {
                await InsertDdnsLogAsync(connection, leaseId, "add_reverse", hostname, ipAddress,
                    result.Fqdn, result.ReverseSuccess, result.ReverseError, config.DnsServer, cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to log DDNS update");
        }
    }

    private async Task LogDdnsRemovalAsync(
        NpgsqlConnection connection,
        Guid leaseId,
        string hostname,
        IPAddress ipAddress,
        DdnsUpdateResult result,
        DdnsConfig config,
        CancellationToken cancellationToken)
    {
        try
        {
            if (result.ForwardSuccess || !string.IsNullOrEmpty(result.ForwardError))
            {
                await InsertDdnsLogAsync(connection, leaseId, "remove_forward", hostname, ipAddress,
                    result.Fqdn, result.ForwardSuccess, result.ForwardError, config.DnsServer, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (result.ReverseSuccess || !string.IsNullOrEmpty(result.ReverseError))
            {
                await InsertDdnsLogAsync(connection, leaseId, "remove_reverse", hostname, ipAddress,
                    result.Fqdn, result.ReverseSuccess, result.ReverseError, config.DnsServer, cancellationToken)
                    .ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to log DDNS removal");
        }
    }

    private static async Task InsertDdnsLogAsync(
        NpgsqlConnection connection,
        Guid leaseId,
        string action,
        string hostname,
        IPAddress ipAddress,
        string? fqdn,
        bool success,
        string? errorMsg,
        IPAddress? dnsServer,
        CancellationToken cancellationToken)
    {
        const string sql = @"
            INSERT INTO dhcp_ddns_log (id, lease_id, action, hostname, ip_address, fqdn, success, error_msg, dns_server)
            VALUES (@id, @leaseId, @action, @hostname, @ip, @fqdn, @success, @error, @dns)";

        await using var cmd = new NpgsqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("id", Guid.NewGuid());
        cmd.Parameters.AddWithValue("leaseId", leaseId);
        cmd.Parameters.AddWithValue("action", action);
        cmd.Parameters.AddWithValue("hostname", hostname);
        cmd.Parameters.AddWithValue("ip", ipAddress);
        cmd.Parameters.AddWithValue("fqdn", fqdn ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("success", success);
        cmd.Parameters.AddWithValue("error", errorMsg ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("dns", dnsServer ?? (object)DBNull.Value);

        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    #endregion
}
