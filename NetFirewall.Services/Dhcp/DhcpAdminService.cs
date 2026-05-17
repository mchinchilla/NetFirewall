using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Dhcp;
using Npgsql;

namespace NetFirewall.Services.Dhcp;

/// <summary>
/// DHCP administration service for the web UI.
/// Provides CRUD operations for subnets, pools, leases, and reservations.
/// </summary>
public sealed class DhcpAdminService : IDhcpAdminService
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly ILogger<DhcpAdminService> _logger;
    private readonly IDhcpCacheNotifier _notifier;

    public DhcpAdminService(NpgsqlDataSource dataSource, ILogger<DhcpAdminService> logger, IDhcpCacheNotifier notifier)
    {
        _dataSource = dataSource;
        _logger = logger;
        _notifier = notifier;
    }

    /// <summary>Convenience: emit a NOTIFY so the DhcpServer drops its cache.</summary>
    private Task NotifyAsync(string reason, CancellationToken ct) => _notifier.NotifySubnetChangedAsync(reason, ct);

    #region Subnet Operations

    public async Task<IReadOnlyList<DhcpSubnet>> GetSubnetsAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "SELECT * FROM dhcp_subnets ORDER BY name";

        await using var cmd = new NpgsqlCommand(sql, conn);
        return await ReadSubnetsAsync(cmd, ct);
    }

    public async Task<DhcpSubnet?> GetSubnetByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "SELECT * FROM dhcp_subnets WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var results = await ReadSubnetsAsync(cmd, ct);
        return results.FirstOrDefault();
    }

    public async Task<DhcpSubnet> CreateSubnetAsync(DhcpSubnet subnet, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        subnet.Id = Guid.NewGuid();
        subnet.CreatedAt = DateTime.UtcNow;
        subnet.UpdatedAt = DateTime.UtcNow;

        const string sql = @"
            INSERT INTO dhcp_subnets (id, name, network, subnet_mask, router, broadcast, domain_name,
                dns_servers, ntp_servers, wins_servers, default_lease_time, max_lease_time, interface_mtu,
                tftp_server, boot_filename, boot_filename_uefi, domain_search, static_routes,
                time_offset, posix_timezone, interface_id, enabled, created_at, updated_at)
            VALUES (@id, @name, @network, @mask, @router, @broadcast, @domain, @dns, @ntp, @wins, @defLease, @maxLease,
                @mtu, @tftp, @bootFile, @bootFileUefi, @domainSearch, @routes::jsonb, @timeOffset, @posixTz,
                @ifaceId, @enabled, @created, @updated)";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddSubnetParams(cmd, subnet);

        await cmd.ExecuteNonQueryAsync(ct);
        _logger.LogInformation("Created subnet {Name} ({Network})", subnet.Name, subnet.Network);

        await NotifyAsync($"subnet.create:{subnet.Id}", ct);
        return subnet;
    }

    public async Task<DhcpSubnet> UpdateSubnetAsync(DhcpSubnet subnet, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        subnet.UpdatedAt = DateTime.UtcNow;

        const string sql = @"
            UPDATE dhcp_subnets SET
                name = @name, network = @network, subnet_mask = @mask, router = @router, broadcast = @broadcast,
                domain_name = @domain, dns_servers = @dns, ntp_servers = @ntp, wins_servers = @wins,
                default_lease_time = @defLease, max_lease_time = @maxLease, interface_mtu = @mtu,
                tftp_server = @tftp, boot_filename = @bootFile, boot_filename_uefi = @bootFileUefi,
                domain_search = @domainSearch, static_routes = @routes::jsonb, time_offset = @timeOffset,
                posix_timezone = @posixTz, interface_id = @ifaceId, enabled = @enabled, updated_at = @updated
            WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddSubnetParams(cmd, subnet);

        await cmd.ExecuteNonQueryAsync(ct);
        _logger.LogInformation("Updated subnet {Name}", subnet.Name);

        await NotifyAsync($"subnet.update:{subnet.Id}", ct);
        return subnet;
    }

    public async Task<bool> DeleteSubnetAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM dhcp_subnets WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var rows = await cmd.ExecuteNonQueryAsync(ct);
        if (rows > 0)
        {
            _logger.LogInformation("Deleted subnet {Id}", id);
            await NotifyAsync($"subnet.delete:{id}", ct);
        }

        return rows > 0;
    }

    private static void AddSubnetParams(NpgsqlCommand cmd, DhcpSubnet subnet)
    {
        cmd.Parameters.AddWithValue("id", subnet.Id);
        cmd.Parameters.AddWithValue("name", subnet.Name);
        // 'cidr' columns in Npgsql 10 take IPNetwork, not string. Parse the
        // model's "addr/prefix" form once on the way in.
        cmd.Parameters.AddWithValue("network", IPNetwork.Parse(subnet.Network));
        cmd.Parameters.AddWithValue("mask", (object?)subnet.SubnetMask ?? DBNull.Value);
        cmd.Parameters.AddWithValue("router", subnet.Router ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("broadcast", subnet.Broadcast ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("domain", subnet.DomainName ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("dns", subnet.DnsServers ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("ntp", subnet.NtpServers ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("wins", subnet.WinsServers ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("defLease", subnet.DefaultLeaseTime);
        cmd.Parameters.AddWithValue("maxLease", subnet.MaxLeaseTime);
        cmd.Parameters.AddWithValue("mtu", subnet.InterfaceMtu ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("tftp", subnet.TftpServer ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("bootFile", subnet.BootFilename ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("bootFileUefi", subnet.BootFilenameUefi ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("domainSearch", subnet.DomainSearchList ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("routes", subnet.StaticRoutesJson ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("timeOffset", subnet.TimeOffset ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("posixTz", subnet.PosixTimezone ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("ifaceId", subnet.InterfaceId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("enabled", subnet.Enabled);
        cmd.Parameters.AddWithValue("created", subnet.CreatedAt);
        cmd.Parameters.AddWithValue("updated", subnet.UpdatedAt);
    }

    private static async Task<IReadOnlyList<DhcpSubnet>> ReadSubnetsAsync(NpgsqlCommand cmd, CancellationToken ct)
    {
        var list = new List<DhcpSubnet>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            list.Add(new DhcpSubnet
            {
                Id = reader.GetGuid(reader.GetOrdinal("id")),
                Name = reader.GetString(reader.GetOrdinal("name")),
                // PostgreSQL 'cidr' maps to System.Net.IPNetwork in Npgsql 10
                // (NpgsqlCidr was deprecated). Format back to "addr/prefix" for
                // the model's string-based Network field.
                Network = reader.GetFieldValue<IPNetwork>(reader.GetOrdinal("network")).ToString(),
                SubnetMask = reader.GetFieldValue<IPAddress>(reader.GetOrdinal("subnet_mask")),
                Router = reader.IsDBNull(reader.GetOrdinal("router")) ? null : reader.GetFieldValue<IPAddress>(reader.GetOrdinal("router")),
                Broadcast = reader.IsDBNull(reader.GetOrdinal("broadcast")) ? null : reader.GetFieldValue<IPAddress>(reader.GetOrdinal("broadcast")),
                DomainName = reader.IsDBNull(reader.GetOrdinal("domain_name")) ? null : reader.GetString(reader.GetOrdinal("domain_name")),
                DnsServers = reader.IsDBNull(reader.GetOrdinal("dns_servers")) ? null : reader.GetFieldValue<IPAddress[]>(reader.GetOrdinal("dns_servers")),
                NtpServers = reader.IsDBNull(reader.GetOrdinal("ntp_servers")) ? null : reader.GetFieldValue<IPAddress[]>(reader.GetOrdinal("ntp_servers")),
                WinsServers = reader.IsDBNull(reader.GetOrdinal("wins_servers")) ? null : reader.GetFieldValue<IPAddress[]>(reader.GetOrdinal("wins_servers")),
                DefaultLeaseTime = reader.GetInt32(reader.GetOrdinal("default_lease_time")),
                MaxLeaseTime = reader.GetInt32(reader.GetOrdinal("max_lease_time")),
                InterfaceMtu = reader.IsDBNull(reader.GetOrdinal("interface_mtu")) ? null : reader.GetInt32(reader.GetOrdinal("interface_mtu")),
                TftpServer = reader.IsDBNull(reader.GetOrdinal("tftp_server")) ? null : reader.GetString(reader.GetOrdinal("tftp_server")),
                BootFilename = reader.IsDBNull(reader.GetOrdinal("boot_filename")) ? null : reader.GetString(reader.GetOrdinal("boot_filename")),
                BootFilenameUefi = reader.IsDBNull(reader.GetOrdinal("boot_filename_uefi")) ? null : reader.GetString(reader.GetOrdinal("boot_filename_uefi")),
                DomainSearchList = reader.IsDBNull(reader.GetOrdinal("domain_search")) ? null : reader.GetString(reader.GetOrdinal("domain_search")),
                StaticRoutesJson = reader.IsDBNull(reader.GetOrdinal("static_routes")) ? null : reader.GetString(reader.GetOrdinal("static_routes")),
                TimeOffset = reader.IsDBNull(reader.GetOrdinal("time_offset")) ? null : reader.GetInt32(reader.GetOrdinal("time_offset")),
                PosixTimezone = reader.IsDBNull(reader.GetOrdinal("posix_timezone")) ? null : reader.GetString(reader.GetOrdinal("posix_timezone")),
                InterfaceId = reader.IsDBNull(reader.GetOrdinal("interface_id")) ? null : reader.GetGuid(reader.GetOrdinal("interface_id")),
                Enabled = reader.GetBoolean(reader.GetOrdinal("enabled")),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at")),
                UpdatedAt = reader.GetDateTime(reader.GetOrdinal("updated_at"))
            });
        }

        return list;
    }

    #endregion

    #region Pool Operations

    public async Task<IReadOnlyList<DhcpPool>> GetPoolsAsync(Guid? subnetId = null, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        var sql = "SELECT * FROM dhcp_pools";
        if (subnetId.HasValue) sql += " WHERE subnet_id = @subnetId";
        sql += " ORDER BY priority, range_start";

        await using var cmd = new NpgsqlCommand(sql, conn);
        if (subnetId.HasValue) cmd.Parameters.AddWithValue("subnetId", subnetId.Value);

        var list = new List<DhcpPool>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            list.Add(new DhcpPool
            {
                Id = reader.GetGuid(reader.GetOrdinal("id")),
                SubnetId = reader.IsDBNull(reader.GetOrdinal("subnet_id")) ? null : reader.GetGuid(reader.GetOrdinal("subnet_id")),
                Name = reader.IsDBNull(reader.GetOrdinal("name")) ? null : reader.GetString(reader.GetOrdinal("name")),
                RangeStart = reader.GetFieldValue<IPAddress>(reader.GetOrdinal("range_start")),
                RangeEnd = reader.GetFieldValue<IPAddress>(reader.GetOrdinal("range_end")),
                AllowUnknownClients = reader.GetBoolean(reader.GetOrdinal("allow_unknown_clients")),
                DenyBootp = reader.GetBoolean(reader.GetOrdinal("deny_bootp")),
                KnownClientsOnly = reader.GetBoolean(reader.GetOrdinal("known_clients_only")),
                Priority = reader.GetInt32(reader.GetOrdinal("priority")),
                Enabled = reader.GetBoolean(reader.GetOrdinal("enabled")),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at"))
            });
        }

        return list;
    }

    public async Task<DhcpPool> CreatePoolAsync(DhcpPool pool, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        pool.Id = Guid.NewGuid();
        pool.CreatedAt = DateTime.UtcNow;

        const string sql = @"
            INSERT INTO dhcp_pools (id, subnet_id, name, range_start, range_end, allow_unknown_clients,
                deny_bootp, known_clients_only, priority, enabled, created_at)
            VALUES (@id, @subnet, @name, @start, @end, @allowUnknown, @denyBootp, @knownOnly, @priority, @enabled, @created)";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", pool.Id);
        cmd.Parameters.AddWithValue("subnet", pool.SubnetId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("name", pool.Name ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("start", pool.RangeStart);
        cmd.Parameters.AddWithValue("end", pool.RangeEnd);
        cmd.Parameters.AddWithValue("allowUnknown", pool.AllowUnknownClients);
        cmd.Parameters.AddWithValue("denyBootp", pool.DenyBootp);
        cmd.Parameters.AddWithValue("knownOnly", pool.KnownClientsOnly);
        cmd.Parameters.AddWithValue("priority", pool.Priority);
        cmd.Parameters.AddWithValue("enabled", pool.Enabled);
        cmd.Parameters.AddWithValue("created", pool.CreatedAt);

        await cmd.ExecuteNonQueryAsync(ct);
        await NotifyAsync($"pool.create:{pool.Id}", ct);
        return pool;
    }

    public async Task<DhcpPool> UpdatePoolAsync(DhcpPool pool, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = @"
            UPDATE dhcp_pools SET
                subnet_id = @subnet, name = @name, range_start = @start, range_end = @end,
                allow_unknown_clients = @allowUnknown, deny_bootp = @denyBootp,
                known_clients_only = @knownOnly, priority = @priority, enabled = @enabled
            WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", pool.Id);
        cmd.Parameters.AddWithValue("subnet", pool.SubnetId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("name", pool.Name ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("start", pool.RangeStart);
        cmd.Parameters.AddWithValue("end", pool.RangeEnd);
        cmd.Parameters.AddWithValue("allowUnknown", pool.AllowUnknownClients);
        cmd.Parameters.AddWithValue("denyBootp", pool.DenyBootp);
        cmd.Parameters.AddWithValue("knownOnly", pool.KnownClientsOnly);
        cmd.Parameters.AddWithValue("priority", pool.Priority);
        cmd.Parameters.AddWithValue("enabled", pool.Enabled);

        await cmd.ExecuteNonQueryAsync(ct);
        await NotifyAsync($"pool.update:{pool.Id}", ct);
        return pool;
    }

    public async Task<bool> DeletePoolAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM dhcp_pools WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var rows = await cmd.ExecuteNonQueryAsync(ct);
        if (rows > 0) await NotifyAsync($"pool.delete:{id}", ct);
        return rows > 0;
    }

    #endregion

    #region Lease Operations

    public async Task<IReadOnlyList<DhcpLease>> GetActiveLeasesAsync(CancellationToken ct = default)
    {
        return await GetAllLeasesAsync(includeExpired: false, ct);
    }

    public async Task<IReadOnlyList<DhcpLease>> GetAllLeasesAsync(bool includeExpired = false, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        var sql = "SELECT * FROM dhcp_leases";
        if (!includeExpired) sql += " WHERE end_time > @now";
        sql += " ORDER BY start_time DESC";

        await using var cmd = new NpgsqlCommand(sql, conn);
        if (!includeExpired) cmd.Parameters.AddWithValue("now", DateTime.UtcNow);

        var list = new List<DhcpLease>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            list.Add(new DhcpLease
            {
                Id = reader.GetGuid(reader.GetOrdinal("id")),
                MacAddress = reader.GetFieldValue<PhysicalAddress>(reader.GetOrdinal("mac_address")),
                IpAddress = reader.GetFieldValue<IPAddress>(reader.GetOrdinal("ip_address")),
                Hostname = reader.IsDBNull(reader.GetOrdinal("hostname")) ? null : reader.GetString(reader.GetOrdinal("hostname")),
                StartTime = reader.GetDateTime(reader.GetOrdinal("start_time")),
                EndTime = reader.GetDateTime(reader.GetOrdinal("end_time"))
            });
        }

        return list;
    }

    public async Task<DhcpLease?> GetLeaseByMacAsync(string macAddress, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = "SELECT * FROM dhcp_leases WHERE mac_address = @mac ORDER BY end_time DESC LIMIT 1";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("mac", PhysicalAddress.Parse(macAddress.Replace(":", "-")));

        await using var reader = await cmd.ExecuteReaderAsync(ct);

        if (await reader.ReadAsync(ct))
        {
            return new DhcpLease
            {
                Id = reader.GetGuid(reader.GetOrdinal("id")),
                MacAddress = reader.GetFieldValue<PhysicalAddress>(reader.GetOrdinal("mac_address")),
                IpAddress = reader.GetFieldValue<IPAddress>(reader.GetOrdinal("ip_address")),
                Hostname = reader.IsDBNull(reader.GetOrdinal("hostname")) ? null : reader.GetString(reader.GetOrdinal("hostname")),
                StartTime = reader.GetDateTime(reader.GetOrdinal("start_time")),
                EndTime = reader.GetDateTime(reader.GetOrdinal("end_time"))
            };
        }

        return null;
    }

    public async Task<bool> ReleaseLeaseAsync(Guid leaseId, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM dhcp_leases WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", leaseId);

        var rows = await cmd.ExecuteNonQueryAsync(ct);
        if (rows > 0) _logger.LogInformation("Released lease {Id}", leaseId);

        return rows > 0;
    }

    public async Task<int> CleanupExpiredLeasesAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM dhcp_leases WHERE end_time < @now";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("now", DateTime.UtcNow);

        var deleted = await cmd.ExecuteNonQueryAsync(ct);
        if (deleted > 0) _logger.LogInformation("Cleaned up {Count} expired leases", deleted);

        return deleted;
    }

    #endregion

    #region Reservation Operations

    public async Task<IReadOnlyList<DhcpMacReservation>> GetReservationsAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "SELECT * FROM dhcp_mac_reservations ORDER BY reserved_ip";

        await using var cmd = new NpgsqlCommand(sql, conn);
        var list = new List<DhcpMacReservation>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            list.Add(new DhcpMacReservation
            {
                Id = reader.GetGuid(reader.GetOrdinal("id")),
                MacAddress = reader.GetFieldValue<PhysicalAddress>(reader.GetOrdinal("mac_address")),
                ReservedIp = reader.GetFieldValue<IPAddress>(reader.GetOrdinal("reserved_ip")),
                Description = reader.IsDBNull(reader.GetOrdinal("description")) ? null : reader.GetString(reader.GetOrdinal("description"))
            });
        }

        return list;
    }

    public async Task<DhcpMacReservation?> GetReservationByIdAsync(Guid id, CancellationToken ct = default)
    {
        var reservations = await GetReservationsAsync(ct);
        return reservations.FirstOrDefault(r => r.Id == id);
    }

    public async Task<DhcpMacReservation> CreateReservationAsync(DhcpMacReservation reservation, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        // Validate IP is not already reserved by another device
        await using (var checkIp = new NpgsqlCommand(
            "SELECT mac_address FROM dhcp_mac_reservations WHERE reserved_ip = @ip LIMIT 1", conn))
        {
            checkIp.Parameters.AddWithValue("ip", reservation.ReservedIp);
            await using var reader = await checkIp.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                var existingMac = reader.GetFieldValue<PhysicalAddress>(0);
                var macBytes = existingMac.GetAddressBytes();
                var macStr = string.Join(":", macBytes.Select(b => b.ToString("X2")));
                throw new InvalidOperationException(
                    $"IP {reservation.ReservedIp} is already reserved for MAC {macStr}");
            }
        }

        // Validate MAC does not already have a reservation
        await using (var checkMac = new NpgsqlCommand(
            "SELECT reserved_ip FROM dhcp_mac_reservations WHERE mac_address = @mac LIMIT 1", conn))
        {
            checkMac.Parameters.AddWithValue("mac", reservation.MacAddress);
            await using var reader = await checkMac.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                var existingIp = reader.GetFieldValue<IPAddress>(0);
                throw new InvalidOperationException(
                    $"MAC {FormatMacAddress(reservation.MacAddress)} already has a reservation for IP {existingIp}");
            }
        }

        reservation.Id = Guid.NewGuid();

        const string sql = @"
            INSERT INTO dhcp_mac_reservations (id, mac_address, reserved_ip, description)
            VALUES (@id, @mac, @ip, @desc)";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", reservation.Id);
        cmd.Parameters.AddWithValue("mac", reservation.MacAddress);
        cmd.Parameters.AddWithValue("ip", reservation.ReservedIp);
        cmd.Parameters.AddWithValue("desc", reservation.Description ?? (object)DBNull.Value);

        await cmd.ExecuteNonQueryAsync(ct);
        _logger.LogInformation("Created reservation {Mac} -> {Ip}", reservation.MacAddress, reservation.ReservedIp);

        await NotifyAsync($"reservation.create:{reservation.Id}", ct);
        return reservation;
    }

    public async Task<DhcpMacReservation> UpdateReservationAsync(DhcpMacReservation reservation, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        // Validate IP is not already reserved by another device (excluding self)
        await using (var checkIp = new NpgsqlCommand(
            "SELECT mac_address FROM dhcp_mac_reservations WHERE reserved_ip = @ip AND id != @id LIMIT 1", conn))
        {
            checkIp.Parameters.AddWithValue("ip", reservation.ReservedIp);
            checkIp.Parameters.AddWithValue("id", reservation.Id);
            await using var reader = await checkIp.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                var existingMac = reader.GetFieldValue<PhysicalAddress>(0);
                var macBytes = existingMac.GetAddressBytes();
                var macStr = string.Join(":", macBytes.Select(b => b.ToString("X2")));
                throw new InvalidOperationException(
                    $"IP {reservation.ReservedIp} is already reserved for MAC {macStr}");
            }
        }

        // Validate MAC does not already have a different reservation (excluding self)
        await using (var checkMac = new NpgsqlCommand(
            "SELECT reserved_ip FROM dhcp_mac_reservations WHERE mac_address = @mac AND id != @id LIMIT 1", conn))
        {
            checkMac.Parameters.AddWithValue("mac", reservation.MacAddress);
            checkMac.Parameters.AddWithValue("id", reservation.Id);
            await using var reader = await checkMac.ExecuteReaderAsync(ct);
            if (await reader.ReadAsync(ct))
            {
                var existingIp = reader.GetFieldValue<IPAddress>(0);
                throw new InvalidOperationException(
                    $"MAC {FormatMacAddress(reservation.MacAddress)} already has a reservation for IP {existingIp}");
            }
        }

        const string sql = @"
            UPDATE dhcp_mac_reservations SET
                mac_address = @mac, reserved_ip = @ip, description = @desc
            WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", reservation.Id);
        cmd.Parameters.AddWithValue("mac", reservation.MacAddress);
        cmd.Parameters.AddWithValue("ip", reservation.ReservedIp);
        cmd.Parameters.AddWithValue("desc", reservation.Description ?? (object)DBNull.Value);

        await cmd.ExecuteNonQueryAsync(ct);
        await NotifyAsync($"reservation.update:{reservation.Id}", ct);
        return reservation;
    }

    public async Task<bool> DeleteReservationAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM dhcp_mac_reservations WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var rows = await cmd.ExecuteNonQueryAsync(ct);
        if (rows > 0)
        {
            _logger.LogInformation("Deleted reservation {Id}", id);
            await NotifyAsync($"reservation.delete:{id}", ct);
        }

        return rows > 0;
    }

    #endregion

    #region Client Class Operations

    public async Task<IReadOnlyList<DhcpClass>> GetClassesAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "SELECT * FROM dhcp_classes ORDER BY priority, name";

        await using var cmd = new NpgsqlCommand(sql, conn);
        return await ReadClassesAsync(cmd, ct);
    }

    public async Task<DhcpClass?> GetClassByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "SELECT * FROM dhcp_classes WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var results = await ReadClassesAsync(cmd, ct);
        return results.FirstOrDefault();
    }

    public async Task<DhcpClass> CreateClassAsync(DhcpClass dhcpClass, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        dhcpClass.Id = Guid.NewGuid();
        dhcpClass.CreatedAt = DateTime.UtcNow;

        const string sql = @"
            INSERT INTO dhcp_classes (id, name, match_type, match_value, options, next_server, boot_filename, priority, enabled, created_at)
            VALUES (@id, @name, @matchType, @matchValue, @options::jsonb, @nextServer, @bootFile, @priority, @enabled, @created)";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddClassParams(cmd, dhcpClass);

        await cmd.ExecuteNonQueryAsync(ct);
        _logger.LogInformation("Created client class {Name}", dhcpClass.Name);
        await NotifyAsync($"class.create:{dhcpClass.Id}", ct);

        return dhcpClass;
    }

    public async Task<DhcpClass> UpdateClassAsync(DhcpClass dhcpClass, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = @"
            UPDATE dhcp_classes SET
                name = @name, match_type = @matchType, match_value = @matchValue, options = @options::jsonb,
                next_server = @nextServer, boot_filename = @bootFile, priority = @priority, enabled = @enabled
            WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddClassParams(cmd, dhcpClass);

        await cmd.ExecuteNonQueryAsync(ct);
        _logger.LogInformation("Updated client class {Name}", dhcpClass.Name);
        await NotifyAsync($"class.update:{dhcpClass.Id}", ct);

        return dhcpClass;
    }

    public async Task<bool> DeleteClassAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM dhcp_classes WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var rows = await cmd.ExecuteNonQueryAsync(ct);
        if (rows > 0)
        {
            _logger.LogInformation("Deleted client class {Id}", id);
            await NotifyAsync($"class.delete:{id}", ct);
        }

        return rows > 0;
    }

    public async Task<IReadOnlyList<PoolClassBinding>> GetPoolClassesAsync(Guid poolId, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = @"
            SELECT pc.allow,
                   c.id, c.name, c.match_type, c.match_value, c.options, c.next_server,
                   c.boot_filename, c.priority, c.enabled, c.created_at
            FROM dhcp_pool_classes pc
            JOIN dhcp_classes c ON c.id = pc.class_id
            WHERE pc.pool_id = @pid
            ORDER BY c.priority, c.name";
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("pid", poolId);

        var list = new List<PoolClassBinding>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var allow = reader.GetBoolean(0);
            var c = new DhcpClass
            {
                Id = reader.GetGuid(1),
                Name = reader.GetString(2),
                MatchType = reader.GetString(3),
                MatchValue = reader.GetString(4),
                Options = reader.IsDBNull(5) ? null : reader.GetString(5),
                NextServer = reader.IsDBNull(6) ? null : reader.GetFieldValue<IPAddress>(6),
                BootFilename = reader.IsDBNull(7) ? null : reader.GetString(7),
                Priority = reader.GetInt32(8),
                Enabled = reader.GetBoolean(9),
                CreatedAt = reader.GetDateTime(10)
            };
            list.Add(new PoolClassBinding(poolId, c, allow));
        }
        return list;
    }

    public async Task SetPoolClassAsync(Guid poolId, Guid classId, bool allow, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = @"
            INSERT INTO dhcp_pool_classes (pool_id, class_id, allow)
            VALUES (@p, @c, @a)
            ON CONFLICT (pool_id, class_id) DO UPDATE SET allow = EXCLUDED.allow";
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("p", poolId);
        cmd.Parameters.AddWithValue("c", classId);
        cmd.Parameters.AddWithValue("a", allow);
        await cmd.ExecuteNonQueryAsync(ct);
        await NotifyAsync($"pool_class.set:{poolId}/{classId}", ct);
    }

    public async Task<bool> RemovePoolClassAsync(Guid poolId, Guid classId, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM dhcp_pool_classes WHERE pool_id = @p AND class_id = @c";
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("p", poolId);
        cmd.Parameters.AddWithValue("c", classId);
        var rows = await cmd.ExecuteNonQueryAsync(ct);
        if (rows > 0) await NotifyAsync($"pool_class.remove:{poolId}/{classId}", ct);
        return rows > 0;
    }

    private static void AddClassParams(NpgsqlCommand cmd, DhcpClass dhcpClass)
    {
        cmd.Parameters.AddWithValue("id", dhcpClass.Id);
        cmd.Parameters.AddWithValue("name", dhcpClass.Name);
        cmd.Parameters.AddWithValue("matchType", dhcpClass.MatchType);
        cmd.Parameters.AddWithValue("matchValue", dhcpClass.MatchValue);
        cmd.Parameters.AddWithValue("options", dhcpClass.Options ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("nextServer", dhcpClass.NextServer ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("bootFile", dhcpClass.BootFilename ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("priority", dhcpClass.Priority);
        cmd.Parameters.AddWithValue("enabled", dhcpClass.Enabled);
        cmd.Parameters.AddWithValue("created", dhcpClass.CreatedAt);
    }

    private static async Task<IReadOnlyList<DhcpClass>> ReadClassesAsync(NpgsqlCommand cmd, CancellationToken ct)
    {
        var list = new List<DhcpClass>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            list.Add(new DhcpClass
            {
                Id = reader.GetGuid(reader.GetOrdinal("id")),
                Name = reader.GetString(reader.GetOrdinal("name")),
                MatchType = reader.GetString(reader.GetOrdinal("match_type")),
                MatchValue = reader.GetString(reader.GetOrdinal("match_value")),
                Options = reader.IsDBNull(reader.GetOrdinal("options")) ? null : reader.GetString(reader.GetOrdinal("options")),
                NextServer = reader.IsDBNull(reader.GetOrdinal("next_server")) ? null : reader.GetFieldValue<IPAddress>(reader.GetOrdinal("next_server")),
                BootFilename = reader.IsDBNull(reader.GetOrdinal("boot_filename")) ? null : reader.GetString(reader.GetOrdinal("boot_filename")),
                Priority = reader.GetInt32(reader.GetOrdinal("priority")),
                Enabled = reader.GetBoolean(reader.GetOrdinal("enabled")),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at"))
            });
        }

        return list;
    }

    #endregion

    #region Exclusion Operations

    public async Task<IReadOnlyList<DhcpExclusion>> GetExclusionsAsync(Guid? subnetId = null, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        var sql = "SELECT * FROM dhcp_exclusions";
        if (subnetId.HasValue) sql += " WHERE subnet_id = @subnetId";
        sql += " ORDER BY ip_start";

        await using var cmd = new NpgsqlCommand(sql, conn);
        if (subnetId.HasValue) cmd.Parameters.AddWithValue("subnetId", subnetId.Value);

        var list = new List<DhcpExclusion>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            list.Add(new DhcpExclusion
            {
                Id = reader.GetGuid(reader.GetOrdinal("id")),
                SubnetId = reader.GetGuid(reader.GetOrdinal("subnet_id")),
                IpStart = reader.GetFieldValue<IPAddress>(reader.GetOrdinal("ip_start")),
                IpEnd = reader.IsDBNull(reader.GetOrdinal("ip_end")) ? null : reader.GetFieldValue<IPAddress>(reader.GetOrdinal("ip_end")),
                Reason = reader.IsDBNull(reader.GetOrdinal("reason")) ? null : reader.GetString(reader.GetOrdinal("reason")),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at"))
            });
        }

        return list;
    }

    public async Task<DhcpExclusion> CreateExclusionAsync(DhcpExclusion exclusion, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        exclusion.Id = Guid.NewGuid();
        exclusion.CreatedAt = DateTime.UtcNow;

        const string sql = @"
            INSERT INTO dhcp_exclusions (id, subnet_id, ip_start, ip_end, reason, created_at)
            VALUES (@id, @subnet, @start, @end, @reason, @created)";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", exclusion.Id);
        cmd.Parameters.AddWithValue("subnet", exclusion.SubnetId);
        cmd.Parameters.AddWithValue("start", exclusion.IpStart);
        cmd.Parameters.AddWithValue("end", exclusion.IpEnd ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("reason", exclusion.Reason ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("created", exclusion.CreatedAt);

        await cmd.ExecuteNonQueryAsync(ct);
        _logger.LogInformation("Created exclusion {Start} in subnet {Subnet}", exclusion.IpStart, exclusion.SubnetId);

        await NotifyAsync($"exclusion.create:{exclusion.Id}", ct);
        return exclusion;
    }

    public async Task<DhcpExclusion> UpdateExclusionAsync(DhcpExclusion exclusion, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = @"
            UPDATE dhcp_exclusions SET
                subnet_id = @subnet, ip_start = @start, ip_end = @end, reason = @reason
            WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", exclusion.Id);
        cmd.Parameters.AddWithValue("subnet", exclusion.SubnetId);
        cmd.Parameters.AddWithValue("start", exclusion.IpStart);
        cmd.Parameters.AddWithValue("end", exclusion.IpEnd ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("reason", exclusion.Reason ?? (object)DBNull.Value);

        await cmd.ExecuteNonQueryAsync(ct);
        _logger.LogInformation("Updated exclusion {Id}", exclusion.Id);

        await NotifyAsync($"exclusion.update:{exclusion.Id}", ct);
        return exclusion;
    }

    public async Task<bool> DeleteExclusionAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM dhcp_exclusions WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var rows = await cmd.ExecuteNonQueryAsync(ct);
        if (rows > 0)
        {
            _logger.LogInformation("Deleted exclusion {Id}", id);
            await NotifyAsync($"exclusion.delete:{id}", ct);
        }

        return rows > 0;
    }

    #endregion

    #region Statistics

    public async Task<DhcpStats> GetStatsAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = @"
            SELECT
                (SELECT COUNT(*) FROM dhcp_subnets) as total_subnets,
                (SELECT COUNT(*) FROM dhcp_subnets WHERE enabled = true) as active_subnets,
                (SELECT COUNT(*) FROM dhcp_leases) as total_leases,
                (SELECT COUNT(*) FROM dhcp_leases WHERE end_time > NOW()) as active_leases,
                (SELECT COUNT(*) FROM dhcp_mac_reservations) as total_reservations";

        await using var cmd = new NpgsqlCommand(sql, conn);
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        if (await reader.ReadAsync(ct))
        {
            var stats = new DhcpStats
            {
                TotalSubnets = Convert.ToInt32(reader.GetInt64(0)),
                ActiveSubnets = Convert.ToInt32(reader.GetInt64(1)),
                TotalLeases = Convert.ToInt32(reader.GetInt64(2)),
                ActiveLeases = Convert.ToInt32(reader.GetInt64(3)),
                TotalReservations = Convert.ToInt32(reader.GetInt64(4))
            };

            // Calculate pool size from pools
            var pools = await GetPoolsAsync(null, ct);
            stats.TotalPoolSize = pools.Sum(p => CalculatePoolSize(p.RangeStart, p.RangeEnd));
            stats.AvailableIps = stats.TotalPoolSize - stats.ActiveLeases;

            return stats;
        }

        return new DhcpStats();
    }

    private static int CalculatePoolSize(IPAddress start, IPAddress end)
    {
        var startBytes = start.GetAddressBytes();
        var endBytes = end.GetAddressBytes();

        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(startBytes);
            Array.Reverse(endBytes);
        }

        var startInt = BitConverter.ToUInt32(startBytes, 0);
        var endInt = BitConverter.ToUInt32(endBytes, 0);

        return (int)(endInt - startInt + 1);
    }

    #endregion

    #region Failover Status

    public async Task<DhcpFailoverStatus?> GetFailoverStatusAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = @"
            SELECT p.name, p.role, p.peer_address, s.state, s.peer_state, s.last_contact
            FROM dhcp_failover_peers p
            LEFT JOIN dhcp_failover_state s ON p.id = s.peer_id
            WHERE p.enabled = true
            LIMIT 1";

        await using var cmd = new NpgsqlCommand(sql, conn);
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        if (await reader.ReadAsync(ct))
        {
            var localState = reader.IsDBNull(3) ? 0 : reader.GetInt32(3);
            var peerState = reader.IsDBNull(4) ? 0 : reader.GetInt32(4);

            return new DhcpFailoverStatus
            {
                Role = reader.GetString(1),
                PeerAddress = reader.GetFieldValue<IPAddress>(2).ToString(),
                LocalState = GetFailoverStateName(localState),
                PeerState = GetFailoverStateName(peerState),
                LastContact = reader.IsDBNull(5) ? null : reader.GetDateTime(5),
                IsHealthy = localState == 4 || localState == 5 // Normal or CommunicationsInterrupted
            };
        }

        return null;
    }

    private static string GetFailoverStateName(int state) => state switch
    {
        0 => "Startup",
        1 => "RecoverWait",
        2 => "RecoverDone",
        3 => "PotentialConflict",
        4 => "Normal",
        5 => "CommunicationsInterrupted",
        6 => "PartnerDown",
        7 => "Recover",
        8 => "Paused",
        9 => "Shutdown",
        10 => "Conflict",
        11 => "ConflictDone",
        _ => "Unknown"
    };

    private static string FormatMacAddress(PhysicalAddress mac)
    {
        var bytes = mac.GetAddressBytes();
        return string.Join(":", bytes.Select(b => b.ToString("X2")));
    }

    #endregion

    #region DDNS Config

    public async Task<IReadOnlyList<DdnsConfig>> GetDdnsConfigsAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "SELECT * FROM dhcp_ddns_config ORDER BY created_at";

        await using var cmd = new NpgsqlCommand(sql, conn);
        var list = new List<DdnsConfig>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            list.Add(ReadDdnsConfig(reader));
        }

        return list;
    }

    public async Task<DdnsConfig> CreateDdnsConfigAsync(DdnsConfig config, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        config.Id = Guid.NewGuid();
        config.CreatedAt = DateTime.UtcNow;
        config.UpdatedAt = DateTime.UtcNow;

        const string sql = @"
            INSERT INTO dhcp_ddns_config (id, subnet_id, enable_forward, enable_reverse, forward_zone, reverse_zone,
                dns_server, dns_port, tsig_key_name, tsig_key_secret, tsig_algorithm, ttl, update_style,
                override_client_update, allow_client_updates, conflict_resolution, enabled, created_at, updated_at)
            VALUES (@id, @subnet, @fwd, @rev, @fwdZone, @revZone, @dns, @port, @keyName, @keySecret, @algo, @ttl,
                @style, @override, @allowClient, @conflict, @enabled, @created, @updated)";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddDdnsConfigParams(cmd, config);

        await cmd.ExecuteNonQueryAsync(ct);
        return config;
    }

    public async Task<DdnsConfig> UpdateDdnsConfigAsync(DdnsConfig config, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        config.UpdatedAt = DateTime.UtcNow;

        const string sql = @"
            UPDATE dhcp_ddns_config SET
                subnet_id = @subnet, enable_forward = @fwd, enable_reverse = @rev, forward_zone = @fwdZone,
                reverse_zone = @revZone, dns_server = @dns, dns_port = @port, tsig_key_name = @keyName,
                tsig_key_secret = @keySecret, tsig_algorithm = @algo, ttl = @ttl, update_style = @style,
                override_client_update = @override, allow_client_updates = @allowClient,
                conflict_resolution = @conflict, enabled = @enabled, updated_at = @updated
            WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddDdnsConfigParams(cmd, config);

        await cmd.ExecuteNonQueryAsync(ct);
        return config;
    }

    public async Task<bool> DeleteDdnsConfigAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM dhcp_ddns_config WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        return await cmd.ExecuteNonQueryAsync(ct) > 0;
    }

    private static void AddDdnsConfigParams(NpgsqlCommand cmd, DdnsConfig config)
    {
        cmd.Parameters.AddWithValue("id", config.Id);
        cmd.Parameters.AddWithValue("subnet", config.SubnetId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("fwd", config.EnableForward);
        cmd.Parameters.AddWithValue("rev", config.EnableReverse);
        cmd.Parameters.AddWithValue("fwdZone", config.ForwardZone ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("revZone", config.ReverseZone ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("dns", (object?)config.DnsServer ?? DBNull.Value);
        cmd.Parameters.AddWithValue("port", config.DnsPort);
        cmd.Parameters.AddWithValue("keyName", config.TsigKeyName ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("keySecret", config.TsigKeySecret ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("algo", config.TsigAlgorithm);
        cmd.Parameters.AddWithValue("ttl", config.Ttl);
        cmd.Parameters.AddWithValue("style", config.UpdateStyle);
        cmd.Parameters.AddWithValue("override", config.OverrideClientUpdate);
        cmd.Parameters.AddWithValue("allowClient", config.AllowClientUpdates);
        cmd.Parameters.AddWithValue("conflict", config.ConflictResolution);
        cmd.Parameters.AddWithValue("enabled", config.Enabled);
        cmd.Parameters.AddWithValue("created", config.CreatedAt);
        cmd.Parameters.AddWithValue("updated", config.UpdatedAt);
    }

    private static DdnsConfig ReadDdnsConfig(NpgsqlDataReader reader)
    {
        return new DdnsConfig
        {
            Id = reader.GetGuid(reader.GetOrdinal("id")),
            SubnetId = reader.IsDBNull(reader.GetOrdinal("subnet_id")) ? null : reader.GetGuid(reader.GetOrdinal("subnet_id")),
            EnableForward = reader.GetBoolean(reader.GetOrdinal("enable_forward")),
            EnableReverse = reader.GetBoolean(reader.GetOrdinal("enable_reverse")),
            ForwardZone = reader.IsDBNull(reader.GetOrdinal("forward_zone")) ? null : reader.GetString(reader.GetOrdinal("forward_zone")),
            ReverseZone = reader.IsDBNull(reader.GetOrdinal("reverse_zone")) ? null : reader.GetString(reader.GetOrdinal("reverse_zone")),
            DnsServer = reader.GetFieldValue<IPAddress>(reader.GetOrdinal("dns_server")),
            DnsPort = reader.GetInt32(reader.GetOrdinal("dns_port")),
            TsigKeyName = reader.IsDBNull(reader.GetOrdinal("tsig_key_name")) ? null : reader.GetString(reader.GetOrdinal("tsig_key_name")),
            TsigKeySecret = reader.IsDBNull(reader.GetOrdinal("tsig_key_secret")) ? null : reader.GetString(reader.GetOrdinal("tsig_key_secret")),
            TsigAlgorithm = reader.GetString(reader.GetOrdinal("tsig_algorithm")),
            Ttl = reader.GetInt32(reader.GetOrdinal("ttl")),
            UpdateStyle = reader.GetString(reader.GetOrdinal("update_style")),
            OverrideClientUpdate = reader.GetBoolean(reader.GetOrdinal("override_client_update")),
            AllowClientUpdates = reader.GetBoolean(reader.GetOrdinal("allow_client_updates")),
            ConflictResolution = reader.GetString(reader.GetOrdinal("conflict_resolution")),
            Enabled = reader.GetBoolean(reader.GetOrdinal("enabled")),
            CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at")),
            UpdatedAt = reader.GetDateTime(reader.GetOrdinal("updated_at"))
        };
    }

    #endregion

    // =====================================================================
    //  Fetch-by-id helpers + Failover peer CRUD added when the Web admin
    //  pages were built. Same NpgsqlCommand + parameterised SQL pattern.
    // =====================================================================

    public async Task<DhcpExclusion?> GetExclusionByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("SELECT * FROM dhcp_exclusions WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null;
        return new DhcpExclusion
        {
            Id = reader.GetGuid(reader.GetOrdinal("id")),
            SubnetId = reader.GetGuid(reader.GetOrdinal("subnet_id")),
            IpStart = reader.GetFieldValue<IPAddress>(reader.GetOrdinal("ip_start")),
            IpEnd = reader.IsDBNull(reader.GetOrdinal("ip_end")) ? null : reader.GetFieldValue<IPAddress>(reader.GetOrdinal("ip_end")),
            Reason = reader.IsDBNull(reader.GetOrdinal("reason")) ? null : reader.GetString(reader.GetOrdinal("reason")),
            CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at"))
        };
    }

    public async Task<DdnsConfig?> GetDdnsConfigByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("SELECT * FROM dhcp_ddns_config WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null;
        return ReadDdnsRow(reader);
    }

    private static DdnsConfig ReadDdnsRow(NpgsqlDataReader r) => new()
    {
        Id = r.GetGuid(r.GetOrdinal("id")),
        SubnetId = r.IsDBNull(r.GetOrdinal("subnet_id")) ? null : r.GetGuid(r.GetOrdinal("subnet_id")),
        EnableForward = r.GetBoolean(r.GetOrdinal("enable_forward")),
        EnableReverse = r.GetBoolean(r.GetOrdinal("enable_reverse")),
        ForwardZone = r.IsDBNull(r.GetOrdinal("forward_zone")) ? null : r.GetString(r.GetOrdinal("forward_zone")),
        ReverseZone = r.IsDBNull(r.GetOrdinal("reverse_zone")) ? null : r.GetString(r.GetOrdinal("reverse_zone")),
        DnsServer = r.GetFieldValue<IPAddress>(r.GetOrdinal("dns_server")),
        DnsPort = r.GetInt32(r.GetOrdinal("dns_port")),
        TsigKeyName = r.IsDBNull(r.GetOrdinal("tsig_key_name")) ? null : r.GetString(r.GetOrdinal("tsig_key_name")),
        TsigKeySecret = r.IsDBNull(r.GetOrdinal("tsig_key_secret")) ? null : r.GetString(r.GetOrdinal("tsig_key_secret")),
        TsigAlgorithm = r.GetString(r.GetOrdinal("tsig_algorithm")),
        Ttl = r.GetInt32(r.GetOrdinal("ttl")),
        UpdateStyle = r.GetString(r.GetOrdinal("update_style")),
        OverrideClientUpdate = r.GetBoolean(r.GetOrdinal("override_client_update")),
        AllowClientUpdates = r.GetBoolean(r.GetOrdinal("allow_client_updates")),
        ConflictResolution = r.GetString(r.GetOrdinal("conflict_resolution")),
        Enabled = r.GetBoolean(r.GetOrdinal("enabled")),
        CreatedAt = r.GetDateTime(r.GetOrdinal("created_at")),
        UpdatedAt = r.GetDateTime(r.GetOrdinal("updated_at"))
    };

    // ---------- failover peers ----------

    public async Task<IReadOnlyList<FailoverPeer>> GetFailoverPeersAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("SELECT * FROM dhcp_failover_peers ORDER BY name", conn);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var list = new List<FailoverPeer>();
        while (await reader.ReadAsync(ct)) list.Add(ReadFailoverPeer(reader));
        return list;
    }

    public async Task<FailoverPeer?> GetFailoverPeerByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("SELECT * FROM dhcp_failover_peers WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? ReadFailoverPeer(reader) : null;
    }

    public async Task<FailoverPeer> CreateFailoverPeerAsync(FailoverPeer p, CancellationToken ct = default)
    {
        if (p.Id == Guid.Empty) p.Id = Guid.NewGuid();
        if (p.CreatedAt == default) p.CreatedAt = DateTime.UtcNow;

        const string sql = @"
            INSERT INTO dhcp_failover_peers
                (id, name, role, peer_address, peer_port, local_address, local_port,
                 max_response_delay, max_unacked_updates, mclt, split, load_balance_max,
                 auto_partner_down, shared_secret, enabled, created_at)
            VALUES
                (@id, @name, @role, @peer_addr, @peer_port, @local_addr, @local_port,
                 @max_resp, @max_unacked, @mclt, @split, @lb_max,
                 @auto_pd, @secret, @enabled, @created)";

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        BindFailoverPeer(cmd, p);
        await cmd.ExecuteNonQueryAsync(ct);
        return p;
    }

    public async Task<FailoverPeer> UpdateFailoverPeerAsync(FailoverPeer p, CancellationToken ct = default)
    {
        const string sql = @"
            UPDATE dhcp_failover_peers SET
                name = @name, role = @role,
                peer_address = @peer_addr, peer_port = @peer_port,
                local_address = @local_addr, local_port = @local_port,
                max_response_delay = @max_resp, max_unacked_updates = @max_unacked,
                mclt = @mclt, split = @split, load_balance_max = @lb_max,
                auto_partner_down = @auto_pd, shared_secret = @secret, enabled = @enabled
            WHERE id = @id";

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        BindFailoverPeer(cmd, p);
        await cmd.ExecuteNonQueryAsync(ct);
        return p;
    }

    public async Task<bool> DeleteFailoverPeerAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("DELETE FROM dhcp_failover_peers WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        return await cmd.ExecuteNonQueryAsync(ct) > 0;
    }

    private static void BindFailoverPeer(NpgsqlCommand cmd, FailoverPeer p)
    {
        cmd.Parameters.AddWithValue("id",          p.Id);
        cmd.Parameters.AddWithValue("name",        p.Name);
        cmd.Parameters.AddWithValue("role",        p.Role);
        cmd.Parameters.AddWithValue("peer_addr",   p.PeerAddress);
        cmd.Parameters.AddWithValue("peer_port",   p.PeerPort);
        var pl = cmd.Parameters.Add("local_addr", NpgsqlTypes.NpgsqlDbType.Inet);
        pl.Value = (object?)p.LocalAddress ?? DBNull.Value;
        cmd.Parameters.AddWithValue("local_port",  p.LocalPort);
        cmd.Parameters.AddWithValue("max_resp",    p.MaxResponseDelay);
        cmd.Parameters.AddWithValue("max_unacked", p.MaxUnackedUpdates);
        cmd.Parameters.AddWithValue("mclt",        p.Mclt);
        cmd.Parameters.AddWithValue("split",       p.Split);
        cmd.Parameters.AddWithValue("lb_max",      p.LoadBalanceMax);
        cmd.Parameters.AddWithValue("auto_pd",     p.AutoPartnerDown);
        cmd.Parameters.AddWithValue("secret",      (object?)p.SharedSecret ?? DBNull.Value);
        cmd.Parameters.AddWithValue("enabled",     p.Enabled);
        cmd.Parameters.AddWithValue("created",     p.CreatedAt);
    }

    private static FailoverPeer ReadFailoverPeer(NpgsqlDataReader r) => new()
    {
        Id              = r.GetGuid(r.GetOrdinal("id")),
        Name            = r.GetString(r.GetOrdinal("name")),
        Role            = r.GetString(r.GetOrdinal("role")),
        PeerAddress     = r.GetFieldValue<IPAddress>(r.GetOrdinal("peer_address")),
        PeerPort        = r.GetInt32(r.GetOrdinal("peer_port")),
        LocalAddress    = r.IsDBNull(r.GetOrdinal("local_address")) ? null : r.GetFieldValue<IPAddress>(r.GetOrdinal("local_address")),
        LocalPort       = r.GetInt32(r.GetOrdinal("local_port")),
        MaxResponseDelay = r.GetInt32(r.GetOrdinal("max_response_delay")),
        MaxUnackedUpdates = r.GetInt32(r.GetOrdinal("max_unacked_updates")),
        Mclt            = r.GetInt32(r.GetOrdinal("mclt")),
        Split           = r.GetInt32(r.GetOrdinal("split")),
        LoadBalanceMax  = r.GetInt32(r.GetOrdinal("load_balance_max")),
        AutoPartnerDown = r.GetInt32(r.GetOrdinal("auto_partner_down")),
        SharedSecret    = r.IsDBNull(r.GetOrdinal("shared_secret")) ? null : r.GetString(r.GetOrdinal("shared_secret")),
        Enabled         = r.GetBoolean(r.GetOrdinal("enabled")),
        CreatedAt       = r.GetDateTime(r.GetOrdinal("created_at"))
    };
}
