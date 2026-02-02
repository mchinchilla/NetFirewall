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

    public DhcpAdminService(NpgsqlDataSource dataSource, ILogger<DhcpAdminService> logger)
    {
        _dataSource = dataSource;
        _logger = logger;
    }

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
                time_offset, posix_timezone, interface_name, enabled, created_at, updated_at)
            VALUES (@id, @name, @network, @mask, @router, @broadcast, @domain, @dns, @ntp, @wins, @defLease, @maxLease,
                @mtu, @tftp, @bootFile, @bootFileUefi, @domainSearch, @routes::jsonb, @timeOffset, @posixTz,
                @iface, @enabled, @created, @updated)";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddSubnetParams(cmd, subnet);

        await cmd.ExecuteNonQueryAsync(ct);
        _logger.LogInformation("Created subnet {Name} ({Network})", subnet.Name, subnet.Network);

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
                posix_timezone = @posixTz, interface_name = @iface, enabled = @enabled, updated_at = @updated
            WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddSubnetParams(cmd, subnet);

        await cmd.ExecuteNonQueryAsync(ct);
        _logger.LogInformation("Updated subnet {Name}", subnet.Name);

        return subnet;
    }

    public async Task<bool> DeleteSubnetAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM dhcp_subnets WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var rows = await cmd.ExecuteNonQueryAsync(ct);
        if (rows > 0) _logger.LogInformation("Deleted subnet {Id}", id);

        return rows > 0;
    }

    private static void AddSubnetParams(NpgsqlCommand cmd, DhcpSubnet subnet)
    {
        cmd.Parameters.AddWithValue("id", subnet.Id);
        cmd.Parameters.AddWithValue("name", subnet.Name);
        cmd.Parameters.AddWithValue("network", subnet.Network);
        cmd.Parameters.AddWithValue("mask", subnet.SubnetMask);
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
        cmd.Parameters.AddWithValue("iface", subnet.InterfaceName ?? (object)DBNull.Value);
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
                Network = reader.GetString(reader.GetOrdinal("network")),
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
                InterfaceName = reader.IsDBNull(reader.GetOrdinal("interface_name")) ? null : reader.GetString(reader.GetOrdinal("interface_name")),
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
        return pool;
    }

    public async Task<bool> DeletePoolAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM dhcp_pools WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        return await cmd.ExecuteNonQueryAsync(ct) > 0;
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

        return reservation;
    }

    public async Task<DhcpMacReservation> UpdateReservationAsync(DhcpMacReservation reservation, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

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
        return reservation;
    }

    public async Task<bool> DeleteReservationAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM dhcp_mac_reservations WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var rows = await cmd.ExecuteNonQueryAsync(ct);
        if (rows > 0) _logger.LogInformation("Deleted reservation {Id}", id);

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
        cmd.Parameters.AddWithValue("dns", config.DnsServer);
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
}
