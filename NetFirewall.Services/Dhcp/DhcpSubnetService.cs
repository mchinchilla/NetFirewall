using System.Collections.Concurrent;
using System.Net;
using System.Runtime.CompilerServices;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Dhcp;
using Npgsql;

namespace NetFirewall.Services.Dhcp;

/// <summary>
/// High-performance subnet service with caching for fast subnet lookups.
/// </summary>
public sealed class DhcpSubnetService : IDhcpSubnetService
{
    private readonly ILogger<DhcpSubnetService> _logger;
    private readonly NpgsqlDataSource _dataSource;

    // Cache subnets for fast lookup (refreshed periodically)
    private readonly ConcurrentDictionary<Guid, DhcpSubnet> _subnetCache = new();
    private readonly ConcurrentDictionary<Guid, List<DhcpPool>> _poolCache = new();
    private readonly ConcurrentDictionary<Guid, List<DhcpExclusion>> _exclusionCache = new();
    private readonly ConcurrentDictionary<string, DhcpClass> _classCache = new();

    private DateTime _lastCacheRefresh = DateTime.MinValue;
    private readonly TimeSpan _cacheExpiry = TimeSpan.FromMinutes(5);
    private readonly SemaphoreSlim _cacheLock = new(1, 1);

    public DhcpSubnetService(NpgsqlDataSource dataSource, ILogger<DhcpSubnetService> logger)
    {
        _dataSource = dataSource;
        _logger = logger;
    }

    #region Subnet Selection

    public async Task<DhcpSubnet?> FindSubnetForRequestAsync(
        DhcpRequest request,
        CancellationToken cancellationToken = default)
    {
        await EnsureCacheLoadedAsync(cancellationToken).ConfigureAwait(false);

        // Priority 1: Use giaddr (relay agent) if present and not 0.0.0.0
        if (request.GiAddr != null && !request.GiAddr.Equals(IPAddress.Any))
        {
            var subnet = FindSubnetContainingIp(request.GiAddr);
            if (subnet != null)
            {
                _logger.LogDebug("Found subnet {SubnetName} via relay agent {GiAddr}",
                    subnet.Name, request.GiAddr);
                return subnet;
            }
        }

        // Priority 2: Use ciaddr if client already has an IP
        if (request.CiAddr != null && !request.CiAddr.Equals(IPAddress.Any))
        {
            var subnet = FindSubnetContainingIp(request.CiAddr);
            if (subnet != null)
            {
                _logger.LogDebug("Found subnet {SubnetName} via client IP {CiAddr}",
                    subnet.Name, request.CiAddr);
                return subnet;
            }
        }

        // Priority 3: Use requested IP if specified
        if (request.RequestedIp != null && !request.RequestedIp.Equals(IPAddress.Any))
        {
            var subnet = FindSubnetContainingIp(request.RequestedIp);
            if (subnet != null)
            {
                _logger.LogDebug("Found subnet {SubnetName} via requested IP {RequestedIp}",
                    subnet.Name, request.RequestedIp);
                return subnet;
            }
        }

        // Priority 4: Return first enabled subnet (for direct connections without relay)
        var firstSubnet = _subnetCache.Values
            .Where(s => s.Enabled)
            .OrderBy(s => s.Name)
            .FirstOrDefault();

        if (firstSubnet != null)
        {
            _logger.LogDebug("Using default subnet {SubnetName}", firstSubnet.Name);
        }

        return firstSubnet;
    }

    public async Task<DhcpSubnet?> FindSubnetByNetworkAsync(
        IPAddress ipAddress,
        CancellationToken cancellationToken = default)
    {
        await EnsureCacheLoadedAsync(cancellationToken).ConfigureAwait(false);
        return FindSubnetContainingIp(ipAddress);
    }

    public async Task<DhcpSubnet?> FindSubnetByInterfaceAsync(
        string interfaceName,
        CancellationToken cancellationToken = default)
    {
        await EnsureCacheLoadedAsync(cancellationToken).ConfigureAwait(false);

        return _subnetCache.Values
            .FirstOrDefault(s => s.Enabled &&
                                 string.Equals(s.InterfaceName, interfaceName, StringComparison.OrdinalIgnoreCase));
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private DhcpSubnet? FindSubnetContainingIp(IPAddress ip)
    {
        foreach (var subnet in _subnetCache.Values.Where(s => s.Enabled))
        {
            if (IsIpInNetwork(ip, subnet.Network, subnet.SubnetMask))
            {
                return subnet;
            }
        }
        return null;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsIpInNetwork(IPAddress ip, string networkCidr, IPAddress? subnetMask)
    {
        if (subnetMask == null) return false;

        // Parse CIDR (e.g., "192.168.1.0/24")
        var parts = networkCidr.Split('/');
        if (parts.Length != 2 || !IPAddress.TryParse(parts[0], out var network))
        {
            return false;
        }

        var ipBytes = ip.GetAddressBytes();
        var networkBytes = network.GetAddressBytes();
        var maskBytes = subnetMask.GetAddressBytes();

        for (int i = 0; i < 4; i++)
        {
            if ((ipBytes[i] & maskBytes[i]) != (networkBytes[i] & maskBytes[i]))
            {
                return false;
            }
        }

        return true;
    }

    #endregion

    #region IP Allocation

    public async Task<(IPAddress? Ip, DhcpPool? Pool)> FindAvailableIpInSubnetAsync(
        DhcpSubnet subnet,
        string macAddress,
        DhcpRequest request,
        CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        // Get pools for this subnet
        if (!_poolCache.TryGetValue(subnet.Id, out var pools))
        {
            pools = await LoadPoolsForSubnetAsync(connection, subnet.Id, cancellationToken).ConfigureAwait(false);
        }

        // Filter pools by enabled and client eligibility
        var eligiblePools = pools
            .Where(p => p.Enabled)
            .OrderBy(p => p.Priority)
            .ToList();

        // Check client class for pool restrictions
        var clientClass = await MatchClientClassAsync(request, cancellationToken).ConfigureAwait(false);

        foreach (var pool in eligiblePools)
        {
            // Check if pool allows this client
            if (!IsClientAllowedInPool(pool, request, clientClass))
            {
                continue;
            }

            // Try to find an available IP in this pool
            var ip = await FindAvailableIpInPoolAsync(
                connection, subnet, pool, macAddress, cancellationToken).ConfigureAwait(false);

            if (ip != null)
            {
                return (ip, pool);
            }
        }

        return (null, null);
    }

    private bool IsClientAllowedInPool(DhcpPool pool, DhcpRequest request, DhcpClass? clientClass)
    {
        // Check known clients only
        if (pool.KnownClientsOnly)
        {
            // Would need to check if MAC is in reservations
            // For now, allow all
        }

        // Check BOOTP denial
        if (pool.DenyBootp && request.IsBootp)
        {
            return false;
        }

        // Check unknown clients
        if (!pool.AllowUnknownClients && clientClass == null)
        {
            return false;
        }

        return true;
    }

    private async Task<IPAddress?> FindAvailableIpInPoolAsync(
        NpgsqlConnection connection,
        DhcpSubnet subnet,
        DhcpPool pool,
        string macAddress,
        CancellationToken cancellationToken)
    {
        var now = DateTime.UtcNow;

        // Get exclusions for this subnet
        if (!_exclusionCache.TryGetValue(subnet.Id, out var exclusions))
        {
            exclusions = new List<DhcpExclusion>();
        }

        // Build exclusion check
        var exclusionRanges = exclusions
            .Select(e => (Start: e.IpStart, End: e.IpEnd ?? e.IpStart))
            .ToList();

        // Query for available IP
        const string sql = @"
            WITH pool_ips AS (
                SELECT ip::inet AS ip
                FROM generate_series(
                    @rangeStart::inet - '0.0.0.0'::inet,
                    @rangeEnd::inet - '0.0.0.0'::inet
                ) AS ip_int,
                LATERAL (SELECT (@rangeStart::inet + ip_int - (@rangeStart::inet - '0.0.0.0'::inet))::inet AS ip) AS computed
            ),
            used_ips AS (
                SELECT ip_address FROM dhcp_leases
                WHERE end_time > @now
            ),
            reserved_ips AS (
                SELECT reserved_ip AS ip_address FROM dhcp_mac_reservations
            )
            SELECT ip FROM pool_ips
            WHERE ip NOT IN (SELECT ip_address FROM used_ips)
              AND ip NOT IN (SELECT ip_address FROM reserved_ips)
            ORDER BY ip
            LIMIT 1";

        try
        {
            await using var cmd = new NpgsqlCommand(sql, connection);
            cmd.Parameters.AddWithValue("rangeStart", pool.RangeStart.ToString());
            cmd.Parameters.AddWithValue("rangeEnd", pool.RangeEnd.ToString());
            cmd.Parameters.AddWithValue("now", now);

            var result = await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
            if (result is IPAddress ip)
            {
                // Check against exclusions
                if (!IsIpExcluded(ip, exclusionRanges))
                {
                    return ip;
                }
            }
        }
        catch (PostgresException ex)
        {
            _logger.LogWarning(ex, "Error finding available IP in pool {PoolId}, falling back to iteration", pool.Id);
        }

        // Fallback: iterate through range
        return await FindAvailableIpFallbackAsync(
            connection, pool, exclusionRanges, now, cancellationToken).ConfigureAwait(false);
    }

    private async Task<IPAddress?> FindAvailableIpFallbackAsync(
        NpgsqlConnection connection,
        DhcpPool pool,
        List<(IPAddress Start, IPAddress End)> exclusions,
        DateTime now,
        CancellationToken cancellationToken)
    {
        var current = pool.RangeStart;
        var end = pool.RangeEnd;

        while (CompareIp(current, end) <= 0)
        {
            if (!IsIpExcluded(current, exclusions))
            {
                // Check if IP is available
                const string checkSql = @"
                    SELECT 1 FROM dhcp_leases WHERE ip_address = @ip AND end_time > @now
                    UNION ALL
                    SELECT 1 FROM dhcp_mac_reservations WHERE reserved_ip = @ip
                    LIMIT 1";

                await using var cmd = new NpgsqlCommand(checkSql, connection);
                cmd.Parameters.AddWithValue("ip", current);
                cmd.Parameters.AddWithValue("now", now);

                var exists = await cmd.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
                if (exists == null)
                {
                    return current;
                }
            }

            current = IncrementIp(current);
            if (current == null) break;
        }

        return null;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool IsIpExcluded(IPAddress ip, List<(IPAddress Start, IPAddress End)> exclusions)
    {
        foreach (var (start, end) in exclusions)
        {
            if (CompareIp(ip, start) >= 0 && CompareIp(ip, end) <= 0)
            {
                return true;
            }
        }
        return false;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static int CompareIp(IPAddress a, IPAddress b)
    {
        var aBytes = a.GetAddressBytes();
        var bBytes = b.GetAddressBytes();

        for (int i = 0; i < 4; i++)
        {
            int cmp = aBytes[i].CompareTo(bBytes[i]);
            if (cmp != 0) return cmp;
        }
        return 0;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static IPAddress? IncrementIp(IPAddress ip)
    {
        var bytes = ip.GetAddressBytes();
        for (int i = 3; i >= 0; i--)
        {
            if (++bytes[i] != 0)
                return new IPAddress(bytes);
        }
        return null;
    }

    #endregion

    #region Client Classification

    public async Task<DhcpClass?> MatchClientClassAsync(
        DhcpRequest request,
        CancellationToken cancellationToken = default)
    {
        await EnsureCacheLoadedAsync(cancellationToken).ConfigureAwait(false);

        foreach (var dhcpClass in _classCache.Values.Where(c => c.Enabled).OrderBy(c => c.Priority))
        {
            if (DoesClientMatchClass(request, dhcpClass))
            {
                _logger.LogDebug("Client {Mac} matched class {ClassName}",
                    request.ClientMac, dhcpClass.Name);
                return dhcpClass;
            }
        }

        return null;
    }

    private static bool DoesClientMatchClass(DhcpRequest request, DhcpClass dhcpClass)
    {
        return dhcpClass.MatchType switch
        {
            DhcpClassMatchTypes.VendorClass =>
                request.VendorClassIdentifier?.Contains(dhcpClass.MatchValue, StringComparison.OrdinalIgnoreCase) == true,

            DhcpClassMatchTypes.MacPrefix =>
                request.ClientMac?.StartsWith(dhcpClass.MatchValue, StringComparison.OrdinalIgnoreCase) == true,

            DhcpClassMatchTypes.Hostname =>
                request.Hostname?.Contains(dhcpClass.MatchValue, StringComparison.OrdinalIgnoreCase) == true,

            _ => false
        };
    }

    #endregion

    #region Cache Management

    private async Task EnsureCacheLoadedAsync(CancellationToken cancellationToken)
    {
        if (DateTime.UtcNow - _lastCacheRefresh < _cacheExpiry && _subnetCache.Count > 0)
        {
            return;
        }

        await _cacheLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Double-check after acquiring lock
            if (DateTime.UtcNow - _lastCacheRefresh < _cacheExpiry && _subnetCache.Count > 0)
            {
                return;
            }

            await RefreshCacheAsync(cancellationToken).ConfigureAwait(false);
            _lastCacheRefresh = DateTime.UtcNow;
        }
        finally
        {
            _cacheLock.Release();
        }
    }

    private async Task RefreshCacheAsync(CancellationToken cancellationToken)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        // Load subnets
        const string subnetSql = @"
            SELECT id, name, network, subnet_mask, router, broadcast, domain_name,
                   dns_servers, ntp_servers, wins_servers, default_lease_time, max_lease_time,
                   interface_mtu, tftp_server, boot_filename, boot_filename_uefi,
                   interface_name, enabled, created_at, updated_at
            FROM dhcp_subnets
            WHERE enabled = true
            ORDER BY name";

        await using (var cmd = new NpgsqlCommand(subnetSql, connection))
        await using (var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false))
        {
            _subnetCache.Clear();
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                var subnet = ReadSubnetFromReader(reader);
                _subnetCache[subnet.Id] = subnet;
            }
        }

        // Load pools for each subnet
        foreach (var subnetId in _subnetCache.Keys)
        {
            var pools = await LoadPoolsForSubnetAsync(connection, subnetId, cancellationToken).ConfigureAwait(false);
            _poolCache[subnetId] = pools;
        }

        // Load exclusions
        foreach (var subnetId in _subnetCache.Keys)
        {
            var exclusions = await LoadExclusionsForSubnetAsync(connection, subnetId, cancellationToken).ConfigureAwait(false);
            _exclusionCache[subnetId] = exclusions;
        }

        // Load classes
        await LoadClassesAsync(connection, cancellationToken).ConfigureAwait(false);

        _logger.LogInformation("DHCP cache refreshed: {SubnetCount} subnets, {PoolCount} pools, {ClassCount} classes",
            _subnetCache.Count,
            _poolCache.Values.Sum(p => p.Count),
            _classCache.Count);
    }

    private static DhcpSubnet ReadSubnetFromReader(NpgsqlDataReader reader)
    {
        return new DhcpSubnet
        {
            Id = reader.GetGuid(0),
            Name = reader.GetString(1),
            Network = reader.GetString(2),
            SubnetMask = reader.IsDBNull(3) ? null : (IPAddress)reader.GetValue(3),
            Router = reader.IsDBNull(4) ? null : (IPAddress)reader.GetValue(4),
            Broadcast = reader.IsDBNull(5) ? null : (IPAddress)reader.GetValue(5),
            DomainName = reader.IsDBNull(6) ? null : reader.GetString(6),
            DnsServers = reader.IsDBNull(7) ? null : (IPAddress[])reader.GetValue(7),
            NtpServers = reader.IsDBNull(8) ? null : (IPAddress[])reader.GetValue(8),
            WinsServers = reader.IsDBNull(9) ? null : (IPAddress[])reader.GetValue(9),
            DefaultLeaseTime = reader.GetInt32(10),
            MaxLeaseTime = reader.GetInt32(11),
            InterfaceMtu = reader.IsDBNull(12) ? null : reader.GetInt32(12),
            TftpServer = reader.IsDBNull(13) ? null : reader.GetString(13),
            BootFilename = reader.IsDBNull(14) ? null : reader.GetString(14),
            BootFilenameUefi = reader.IsDBNull(15) ? null : reader.GetString(15),
            InterfaceName = reader.IsDBNull(16) ? null : reader.GetString(16),
            Enabled = reader.GetBoolean(17),
            CreatedAt = reader.GetDateTime(18),
            UpdatedAt = reader.GetDateTime(19)
        };
    }

    private async Task<List<DhcpPool>> LoadPoolsForSubnetAsync(
        NpgsqlConnection connection,
        Guid subnetId,
        CancellationToken cancellationToken)
    {
        const string sql = @"
            SELECT id, subnet_id, name, range_start, range_end,
                   allow_unknown_clients, deny_bootp, known_clients_only,
                   priority, enabled, created_at
            FROM dhcp_pools
            WHERE subnet_id = @subnetId AND enabled = true
            ORDER BY priority, name";

        await using var cmd = new NpgsqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("subnetId", subnetId);

        var pools = new List<DhcpPool>();
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            pools.Add(new DhcpPool
            {
                Id = reader.GetGuid(0),
                SubnetId = reader.GetGuid(1),
                Name = reader.IsDBNull(2) ? null : reader.GetString(2),
                RangeStart = (IPAddress)reader.GetValue(3),
                RangeEnd = (IPAddress)reader.GetValue(4),
                AllowUnknownClients = reader.GetBoolean(5),
                DenyBootp = reader.GetBoolean(6),
                KnownClientsOnly = reader.GetBoolean(7),
                Priority = reader.GetInt32(8),
                Enabled = reader.GetBoolean(9),
                CreatedAt = reader.GetDateTime(10)
            });
        }

        return pools;
    }

    private async Task<List<DhcpExclusion>> LoadExclusionsForSubnetAsync(
        NpgsqlConnection connection,
        Guid subnetId,
        CancellationToken cancellationToken)
    {
        const string sql = @"
            SELECT id, subnet_id, ip_start, ip_end, reason, created_at
            FROM dhcp_exclusions
            WHERE subnet_id = @subnetId";

        await using var cmd = new NpgsqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("subnetId", subnetId);

        var exclusions = new List<DhcpExclusion>();
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            exclusions.Add(new DhcpExclusion
            {
                Id = reader.GetGuid(0),
                SubnetId = reader.GetGuid(1),
                IpStart = (IPAddress)reader.GetValue(2),
                IpEnd = reader.IsDBNull(3) ? null : (IPAddress)reader.GetValue(3),
                Reason = reader.IsDBNull(4) ? null : reader.GetString(4),
                CreatedAt = reader.GetDateTime(5)
            });
        }

        return exclusions;
    }

    private async Task LoadClassesAsync(NpgsqlConnection connection, CancellationToken cancellationToken)
    {
        const string sql = @"
            SELECT id, name, match_type, match_value, options, next_server,
                   boot_filename, priority, enabled, created_at
            FROM dhcp_classes
            WHERE enabled = true
            ORDER BY priority";

        await using var cmd = new NpgsqlCommand(sql, connection);
        await using var reader = await cmd.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);

        _classCache.Clear();
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            var dhcpClass = new DhcpClass
            {
                Id = reader.GetGuid(0),
                Name = reader.GetString(1),
                MatchType = reader.GetString(2),
                MatchValue = reader.GetString(3),
                Options = reader.IsDBNull(4) ? null : reader.GetString(4),
                NextServer = reader.IsDBNull(5) ? null : (IPAddress)reader.GetValue(5),
                BootFilename = reader.IsDBNull(6) ? null : reader.GetString(6),
                Priority = reader.GetInt32(7),
                Enabled = reader.GetBoolean(8),
                CreatedAt = reader.GetDateTime(9)
            };
            _classCache[dhcpClass.Name] = dhcpClass;
        }
    }

    #endregion

    #region CRUD Operations

    public async Task<IReadOnlyList<DhcpSubnet>> GetAllSubnetsAsync(CancellationToken cancellationToken = default)
    {
        await EnsureCacheLoadedAsync(cancellationToken).ConfigureAwait(false);
        return _subnetCache.Values.OrderBy(s => s.Name).ToList();
    }

    public async Task<DhcpSubnet?> GetSubnetWithPoolsAsync(Guid subnetId, CancellationToken cancellationToken = default)
    {
        await EnsureCacheLoadedAsync(cancellationToken).ConfigureAwait(false);

        if (_subnetCache.TryGetValue(subnetId, out var subnet))
        {
            if (_poolCache.TryGetValue(subnetId, out var pools))
            {
                subnet.Pools = pools;
            }
            return subnet;
        }

        return null;
    }

    public async Task<IReadOnlyList<DhcpPool>> GetPoolsForSubnetAsync(
        Guid subnetId,
        CancellationToken cancellationToken = default)
    {
        await EnsureCacheLoadedAsync(cancellationToken).ConfigureAwait(false);

        if (_poolCache.TryGetValue(subnetId, out var pools))
        {
            return pools;
        }

        return Array.Empty<DhcpPool>();
    }

    public async Task<IReadOnlyList<DhcpExclusion>> GetExclusionsForSubnetAsync(
        Guid subnetId,
        CancellationToken cancellationToken = default)
    {
        await EnsureCacheLoadedAsync(cancellationToken).ConfigureAwait(false);

        if (_exclusionCache.TryGetValue(subnetId, out var exclusions))
        {
            return exclusions;
        }

        return Array.Empty<DhcpExclusion>();
    }

    public async Task<DhcpSubnet> CreateSubnetAsync(DhcpSubnet subnet, CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        if (subnet.Id == Guid.Empty)
        {
            subnet.Id = Guid.NewGuid();
        }

        const string sql = @"
            INSERT INTO dhcp_subnets (id, name, network, subnet_mask, router, broadcast, domain_name,
                dns_servers, ntp_servers, wins_servers, default_lease_time, max_lease_time,
                interface_mtu, tftp_server, boot_filename, boot_filename_uefi, interface_name, enabled)
            VALUES (@id, @name, @network::cidr, @subnetMask, @router, @broadcast, @domainName,
                @dnsServers, @ntpServers, @winsServers, @defaultLeaseTime, @maxLeaseTime,
                @interfaceMtu, @tftpServer, @bootFilename, @bootFilenameUefi, @interfaceName, @enabled)";

        await using var cmd = new NpgsqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("id", subnet.Id);
        cmd.Parameters.AddWithValue("name", subnet.Name);
        cmd.Parameters.AddWithValue("network", subnet.Network);
        cmd.Parameters.AddWithValue("subnetMask", (object?)subnet.SubnetMask ?? DBNull.Value);
        cmd.Parameters.AddWithValue("router", (object?)subnet.Router ?? DBNull.Value);
        cmd.Parameters.AddWithValue("broadcast", (object?)subnet.Broadcast ?? DBNull.Value);
        cmd.Parameters.AddWithValue("domainName", (object?)subnet.DomainName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("dnsServers", (object?)subnet.DnsServers ?? DBNull.Value);
        cmd.Parameters.AddWithValue("ntpServers", (object?)subnet.NtpServers ?? DBNull.Value);
        cmd.Parameters.AddWithValue("winsServers", (object?)subnet.WinsServers ?? DBNull.Value);
        cmd.Parameters.AddWithValue("defaultLeaseTime", subnet.DefaultLeaseTime);
        cmd.Parameters.AddWithValue("maxLeaseTime", subnet.MaxLeaseTime);
        cmd.Parameters.AddWithValue("interfaceMtu", (object?)subnet.InterfaceMtu ?? DBNull.Value);
        cmd.Parameters.AddWithValue("tftpServer", (object?)subnet.TftpServer ?? DBNull.Value);
        cmd.Parameters.AddWithValue("bootFilename", (object?)subnet.BootFilename ?? DBNull.Value);
        cmd.Parameters.AddWithValue("bootFilenameUefi", (object?)subnet.BootFilenameUefi ?? DBNull.Value);
        cmd.Parameters.AddWithValue("interfaceName", (object?)subnet.InterfaceName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("enabled", subnet.Enabled);

        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // Invalidate cache
        _lastCacheRefresh = DateTime.MinValue;

        _logger.LogInformation("Created subnet {SubnetName} ({Network})", subnet.Name, subnet.Network);
        return subnet;
    }

    public async Task<DhcpSubnet> UpdateSubnetAsync(DhcpSubnet subnet, CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        const string sql = @"
            UPDATE dhcp_subnets SET
                name = @name, network = @network::cidr, subnet_mask = @subnetMask,
                router = @router, broadcast = @broadcast, domain_name = @domainName,
                dns_servers = @dnsServers, ntp_servers = @ntpServers, wins_servers = @winsServers,
                default_lease_time = @defaultLeaseTime, max_lease_time = @maxLeaseTime,
                interface_mtu = @interfaceMtu, tftp_server = @tftpServer,
                boot_filename = @bootFilename, boot_filename_uefi = @bootFilenameUefi,
                interface_name = @interfaceName, enabled = @enabled, updated_at = @updatedAt
            WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("id", subnet.Id);
        cmd.Parameters.AddWithValue("name", subnet.Name);
        cmd.Parameters.AddWithValue("network", subnet.Network);
        cmd.Parameters.AddWithValue("subnetMask", (object?)subnet.SubnetMask ?? DBNull.Value);
        cmd.Parameters.AddWithValue("router", (object?)subnet.Router ?? DBNull.Value);
        cmd.Parameters.AddWithValue("broadcast", (object?)subnet.Broadcast ?? DBNull.Value);
        cmd.Parameters.AddWithValue("domainName", (object?)subnet.DomainName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("dnsServers", (object?)subnet.DnsServers ?? DBNull.Value);
        cmd.Parameters.AddWithValue("ntpServers", (object?)subnet.NtpServers ?? DBNull.Value);
        cmd.Parameters.AddWithValue("winsServers", (object?)subnet.WinsServers ?? DBNull.Value);
        cmd.Parameters.AddWithValue("defaultLeaseTime", subnet.DefaultLeaseTime);
        cmd.Parameters.AddWithValue("maxLeaseTime", subnet.MaxLeaseTime);
        cmd.Parameters.AddWithValue("interfaceMtu", (object?)subnet.InterfaceMtu ?? DBNull.Value);
        cmd.Parameters.AddWithValue("tftpServer", (object?)subnet.TftpServer ?? DBNull.Value);
        cmd.Parameters.AddWithValue("bootFilename", (object?)subnet.BootFilename ?? DBNull.Value);
        cmd.Parameters.AddWithValue("bootFilenameUefi", (object?)subnet.BootFilenameUefi ?? DBNull.Value);
        cmd.Parameters.AddWithValue("interfaceName", (object?)subnet.InterfaceName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("enabled", subnet.Enabled);
        cmd.Parameters.AddWithValue("updatedAt", DateTime.UtcNow);

        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // Invalidate cache
        _lastCacheRefresh = DateTime.MinValue;

        return subnet;
    }

    public async Task<bool> DeleteSubnetAsync(Guid subnetId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        const string sql = "DELETE FROM dhcp_subnets WHERE id = @id";
        await using var cmd = new NpgsqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("id", subnetId);

        var affected = await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // Invalidate cache
        _lastCacheRefresh = DateTime.MinValue;

        return affected > 0;
    }

    public async Task<DhcpPool> CreatePoolAsync(DhcpPool pool, CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        if (pool.Id == Guid.Empty)
        {
            pool.Id = Guid.NewGuid();
        }

        const string sql = @"
            INSERT INTO dhcp_pools (id, subnet_id, name, range_start, range_end,
                allow_unknown_clients, deny_bootp, known_clients_only, priority, enabled)
            VALUES (@id, @subnetId, @name, @rangeStart, @rangeEnd,
                @allowUnknownClients, @denyBootp, @knownClientsOnly, @priority, @enabled)";

        await using var cmd = new NpgsqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("id", pool.Id);
        cmd.Parameters.AddWithValue("subnetId", pool.SubnetId);
        cmd.Parameters.AddWithValue("name", (object?)pool.Name ?? DBNull.Value);
        cmd.Parameters.AddWithValue("rangeStart", pool.RangeStart);
        cmd.Parameters.AddWithValue("rangeEnd", pool.RangeEnd);
        cmd.Parameters.AddWithValue("allowUnknownClients", pool.AllowUnknownClients);
        cmd.Parameters.AddWithValue("denyBootp", pool.DenyBootp);
        cmd.Parameters.AddWithValue("knownClientsOnly", pool.KnownClientsOnly);
        cmd.Parameters.AddWithValue("priority", pool.Priority);
        cmd.Parameters.AddWithValue("enabled", pool.Enabled);

        await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // Invalidate cache
        _lastCacheRefresh = DateTime.MinValue;

        return pool;
    }

    public async Task<bool> DeletePoolAsync(Guid poolId, CancellationToken cancellationToken = default)
    {
        await using var connection = await _dataSource.OpenConnectionAsync(cancellationToken).ConfigureAwait(false);

        const string sql = "DELETE FROM dhcp_pools WHERE id = @id";
        await using var cmd = new NpgsqlCommand(sql, connection);
        cmd.Parameters.AddWithValue("id", poolId);

        var affected = await cmd.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);

        // Invalidate cache
        _lastCacheRefresh = DateTime.MinValue;

        return affected > 0;
    }

    #endregion
}
