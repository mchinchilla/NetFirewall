using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Network;
using Npgsql;

namespace NetFirewall.Services.Firewall;

/// <summary>System.Text.Json converter for <see cref="IPAddress"/>. The default
/// reflection-based serializer touches the <c>ScopeId</c> getter, which throws
/// <see cref="SocketException"/> ("Operation not supported") on IPv6 addresses
/// that aren't link-local — breaking audit-log writes whenever an interface
/// has any IPv6 attached. Stringify with <c>ToString()</c> instead.</summary>
internal sealed class IPAddressJsonConverter : JsonConverter<IPAddress>
{
    public override IPAddress? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        => reader.GetString() is { } s ? IPAddress.Parse(s) : null;

    public override void Write(Utf8JsonWriter writer, IPAddress value, JsonSerializerOptions options)
        => writer.WriteStringValue(value.ToString());
}

/// <summary>
/// Firewall service for managing nftables configuration stored in PostgreSQL.
/// Provides CRUD operations and nftables.conf generation.
/// </summary>
public sealed class FirewallService : IFirewallService
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly INetworkObjectResolver _objectResolver;
    private readonly INetworkServiceResolver _serviceResolver;
    private readonly ILogger<FirewallService> _logger;

    private static readonly JsonSerializerOptions AuditJsonOptions = new()
    {
        Converters = { new IPAddressJsonConverter() }
    };

    public FirewallService(
        NpgsqlDataSource dataSource,
        INetworkObjectResolver objectResolver,
        INetworkServiceResolver serviceResolver,
        ILogger<FirewallService> logger)
    {
        _dataSource = dataSource;
        _objectResolver = objectResolver;
        _serviceResolver = serviceResolver;
        _logger = logger;
    }

    #region Interface Operations

    public async Task<IReadOnlyList<FwInterface>> GetInterfacesAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "SELECT * FROM fw_interfaces ORDER BY type, name";

        await using var cmd = new NpgsqlCommand(sql, conn);
        return await ReadInterfacesAsync(cmd, ct);
    }

    public async Task<FwInterface?> GetInterfaceByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "SELECT * FROM fw_interfaces WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var results = await ReadInterfacesAsync(cmd, ct);
        return results.FirstOrDefault();
    }

    public async Task<FwInterface?> GetInterfaceByNameAsync(string name, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "SELECT * FROM fw_interfaces WHERE name = @name";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("name", name);

        var results = await ReadInterfacesAsync(cmd, ct);
        return results.FirstOrDefault();
    }

    public async Task<FwInterface> CreateInterfaceAsync(FwInterface iface, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        iface.Id = Guid.NewGuid();
        iface.CreatedAt = DateTime.UtcNow;
        iface.UpdatedAt = DateTime.UtcNow;

        const string sql = @"
            INSERT INTO fw_interfaces (id, name, type, role, ip_address, subnet_mask, gateway,
                dns_servers, mtu, vlan_id, vlan_parent, addressing_mode, metric, mac_address,
                description, auto_start, enabled, created_at, updated_at)
            VALUES (@id, @name, @type, @role, @ip, @subnet, @gateway,
                @dns, @mtu, @vlanId, @vlanParent, @addrMode, @metric, @mac,
                @desc, @autoStart, @enabled, @created, @updated)";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddInterfaceParams(cmd, iface);

        await cmd.ExecuteNonQueryAsync(ct);

        await LogAuditAsync("fw_interfaces", iface.Id, "INSERT", null, iface, null, ct);

        _logger.LogInformation("Created interface {Name} ({Type})", iface.Name, iface.Type);
        return iface;
    }

    public async Task<FwInterface> UpdateInterfaceAsync(FwInterface iface, CancellationToken ct = default)
    {
        var existing = await GetInterfaceByIdAsync(iface.Id, ct);

        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        iface.UpdatedAt = DateTime.UtcNow;

        const string sql = @"
            UPDATE fw_interfaces
            SET name = @name, type = @type, role = @role, ip_address = @ip,
                subnet_mask = @subnet, gateway = @gateway, dns_servers = @dns,
                mtu = @mtu, vlan_id = @vlanId, vlan_parent = @vlanParent,
                addressing_mode = @addrMode, metric = @metric, mac_address = @mac,
                description = @desc, auto_start = @autoStart, enabled = @enabled, updated_at = @updated
            WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddInterfaceParams(cmd, iface);

        await cmd.ExecuteNonQueryAsync(ct);

        await LogAuditAsync("fw_interfaces", iface.Id, "UPDATE", existing, iface, null, ct);

        _logger.LogInformation("Updated interface {Name}", iface.Name);
        return iface;
    }

    public async Task<bool> DeleteInterfaceAsync(Guid id, CancellationToken ct = default)
    {
        var existing = await GetInterfaceByIdAsync(id, ct);
        if (existing == null) return false;

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM fw_interfaces WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var rows = await cmd.ExecuteNonQueryAsync(ct);

        if (rows > 0)
        {
            await LogAuditAsync("fw_interfaces", id, "DELETE", existing, null, null, ct);
            _logger.LogInformation("Deleted interface {Name}", existing.Name);
        }

        return rows > 0;
    }

    private static void AddInterfaceParams(NpgsqlCommand cmd, FwInterface iface)
    {
        cmd.Parameters.AddWithValue("id", iface.Id);
        cmd.Parameters.AddWithValue("name", iface.Name);
        cmd.Parameters.AddWithValue("type", iface.Type);
        cmd.Parameters.AddWithValue("role", iface.Role ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("ip", iface.IpAddress ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("subnet", iface.SubnetMask ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("gateway", iface.Gateway ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("dns", iface.DnsServers ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("mtu", iface.Mtu ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("vlanId", iface.VlanId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("vlanParent", iface.VlanParent ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("addrMode", iface.AddressingMode);
        cmd.Parameters.AddWithValue("metric", iface.Metric ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("mac", iface.MacAddress ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("desc", iface.Description ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("autoStart", iface.AutoStart);
        cmd.Parameters.AddWithValue("enabled", iface.Enabled);
        cmd.Parameters.AddWithValue("created", iface.CreatedAt);
        cmd.Parameters.AddWithValue("updated", iface.UpdatedAt);
    }

    private static async Task<IReadOnlyList<FwInterface>> ReadInterfacesAsync(NpgsqlCommand cmd, CancellationToken ct)
    {
        var list = new List<FwInterface>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            var iface = new FwInterface
            {
                Id = reader.GetGuid(reader.GetOrdinal("id")),
                Name = reader.GetString(reader.GetOrdinal("name")),
                Type = reader.GetString(reader.GetOrdinal("type")),
                Role = reader.IsDBNull(reader.GetOrdinal("role")) ? null : reader.GetString(reader.GetOrdinal("role")),
                IpAddress = reader.IsDBNull(reader.GetOrdinal("ip_address")) ? null : reader.GetFieldValue<System.Net.IPAddress>(reader.GetOrdinal("ip_address")),
                SubnetMask = reader.IsDBNull(reader.GetOrdinal("subnet_mask")) ? null : reader.GetFieldValue<System.Net.IPAddress>(reader.GetOrdinal("subnet_mask")),
                Gateway = reader.IsDBNull(reader.GetOrdinal("gateway")) ? null : reader.GetFieldValue<System.Net.IPAddress>(reader.GetOrdinal("gateway")),
                Enabled = reader.GetBoolean(reader.GetOrdinal("enabled")),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at")),
                UpdatedAt = reader.GetDateTime(reader.GetOrdinal("updated_at"))
            };

            // Read new fields with column existence check
            try
            {
                var dnsOrdinal = reader.GetOrdinal("dns_servers");
                iface.DnsServers = reader.IsDBNull(dnsOrdinal) ? null : reader.GetFieldValue<System.Net.IPAddress[]>(dnsOrdinal);
            }
            catch (IndexOutOfRangeException) { /* Column not yet added */ }

            try
            {
                var mtuOrdinal = reader.GetOrdinal("mtu");
                iface.Mtu = reader.IsDBNull(mtuOrdinal) ? null : reader.GetInt32(mtuOrdinal);
            }
            catch (IndexOutOfRangeException) { }

            try
            {
                var vlanIdOrdinal = reader.GetOrdinal("vlan_id");
                iface.VlanId = reader.IsDBNull(vlanIdOrdinal) ? null : reader.GetInt32(vlanIdOrdinal);
            }
            catch (IndexOutOfRangeException) { }

            try
            {
                var vlanParentOrdinal = reader.GetOrdinal("vlan_parent");
                iface.VlanParent = reader.IsDBNull(vlanParentOrdinal) ? null : reader.GetString(vlanParentOrdinal);
            }
            catch (IndexOutOfRangeException) { }

            try
            {
                var addrModeOrdinal = reader.GetOrdinal("addressing_mode");
                iface.AddressingMode = reader.IsDBNull(addrModeOrdinal) ? "static" : reader.GetString(addrModeOrdinal);
            }
            catch (IndexOutOfRangeException) { }

            try
            {
                var metricOrdinal = reader.GetOrdinal("metric");
                iface.Metric = reader.IsDBNull(metricOrdinal) ? null : reader.GetInt32(metricOrdinal);
            }
            catch (IndexOutOfRangeException) { }

            try
            {
                var macOrdinal = reader.GetOrdinal("mac_address");
                iface.MacAddress = reader.IsDBNull(macOrdinal) ? null : reader.GetString(macOrdinal);
            }
            catch (IndexOutOfRangeException) { }

            try
            {
                var descOrdinal = reader.GetOrdinal("description");
                iface.Description = reader.IsDBNull(descOrdinal) ? null : reader.GetString(descOrdinal);
            }
            catch (IndexOutOfRangeException) { }

            try
            {
                var autoStartOrdinal = reader.GetOrdinal("auto_start");
                iface.AutoStart = reader.IsDBNull(autoStartOrdinal) || reader.GetBoolean(autoStartOrdinal);
            }
            catch (IndexOutOfRangeException) { }

            list.Add(iface);
        }

        return list;
    }

    #endregion

    #region Static Route Operations

    public async Task<IReadOnlyList<FwStaticRoute>> GetStaticRoutesAsync(Guid? interfaceId = null, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        // Cast cidr → text so the reader hands us a System.String for destination.
        // `SELECT *` (plus the cidr->text cast) rather than an explicit column
        // list, so table_id is picked up when present and simply absent on a
        // host whose schema predates migration 00023 — the reader tolerates it.
        var sql = @"SELECT *, destination::text AS destination_text
                    FROM fw_static_routes";
        if (interfaceId.HasValue) sql += " WHERE interface_id = @ifaceId";
        sql += " ORDER BY metric, created_at";

        await using var cmd = new NpgsqlCommand(sql, conn);
        if (interfaceId.HasValue) cmd.Parameters.AddWithValue("ifaceId", interfaceId.Value);

        return await ReadStaticRoutesAsync(cmd, ct);
    }

    public async Task<FwStaticRoute?> GetStaticRouteByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = @"SELECT *, destination::text AS destination_text
                             FROM fw_static_routes WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var results = await ReadStaticRoutesAsync(cmd, ct);
        return results.FirstOrDefault();
    }

    public async Task<FwStaticRoute> CreateStaticRouteAsync(FwStaticRoute route, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        route.Id = Guid.NewGuid();
        route.CreatedAt = DateTime.UtcNow;

        const string sql = @"
            INSERT INTO fw_static_routes (id, interface_id, destination, gateway, metric, description, enabled, table_id, created_at)
            VALUES (@id, @ifaceId, @dest::cidr, @gateway, @metric, @desc, @enabled, @tableId, @created)";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddStaticRouteParams(cmd, route);

        await cmd.ExecuteNonQueryAsync(ct);

        await LogAuditAsync("fw_static_routes", route.Id, "INSERT", null, route, null, ct);

        _logger.LogInformation("Created static route {Dest} via {Gateway}", route.Destination, route.Gateway);
        return route;
    }

    public async Task<FwStaticRoute> UpdateStaticRouteAsync(FwStaticRoute route, CancellationToken ct = default)
    {
        var existing = await GetStaticRouteByIdAsync(route.Id, ct);

        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = @"
            UPDATE fw_static_routes
            SET interface_id = @ifaceId, destination = @dest::cidr, gateway = @gateway,
                metric = @metric, description = @desc, enabled = @enabled, table_id = @tableId
            WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddStaticRouteParams(cmd, route);

        await cmd.ExecuteNonQueryAsync(ct);

        await LogAuditAsync("fw_static_routes", route.Id, "UPDATE", existing, route, null, ct);

        _logger.LogInformation("Updated static route {Dest}", route.Destination);
        return route;
    }

    public async Task<bool> DeleteStaticRouteAsync(Guid id, CancellationToken ct = default)
    {
        var existing = await GetStaticRouteByIdAsync(id, ct);
        if (existing == null) return false;

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM fw_static_routes WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var rows = await cmd.ExecuteNonQueryAsync(ct);

        if (rows > 0)
        {
            await LogAuditAsync("fw_static_routes", id, "DELETE", existing, null, null, ct);
            _logger.LogInformation("Deleted static route {Dest}", existing.Destination);
        }

        return rows > 0;
    }

    private static void AddStaticRouteParams(NpgsqlCommand cmd, FwStaticRoute route)
    {
        cmd.Parameters.AddWithValue("id", route.Id);
        cmd.Parameters.AddWithValue("ifaceId", route.InterfaceId);
        cmd.Parameters.AddWithValue("dest", route.Destination);
        cmd.Parameters.AddWithValue("gateway", route.Gateway ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("metric", route.Metric);
        cmd.Parameters.AddWithValue("desc", route.Description ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("enabled", route.Enabled);
        // The named routing table this route lives in. NULL = the main table.
        // Non-null is what makes PolicyRoutingApplyService install it with
        // `ip route replace … table <name>` instead of into main — i.e. it is
        // what wires a route into policy routing at all.
        cmd.Parameters.AddWithValue("tableId", route.TableId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("created", route.CreatedAt);
    }

    private static async Task<IReadOnlyList<FwStaticRoute>> ReadStaticRoutesAsync(NpgsqlCommand cmd, CancellationToken ct)
    {
        var list = new List<FwStaticRoute>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            list.Add(new FwStaticRoute
            {
                Id = reader.GetGuid(reader.GetOrdinal("id")),
                InterfaceId = reader.GetGuid(reader.GetOrdinal("interface_id")),
                Destination = reader.GetString(reader.GetOrdinal("destination_text")),
                Gateway = reader.IsDBNull(reader.GetOrdinal("gateway")) ? null : reader.GetFieldValue<System.Net.IPAddress>(reader.GetOrdinal("gateway")),
                Metric = reader.GetInt32(reader.GetOrdinal("metric")),
                Description = reader.IsDBNull(reader.GetOrdinal("description")) ? null : reader.GetString(reader.GetOrdinal("description")),
                Enabled = reader.GetBoolean(reader.GetOrdinal("enabled")),
                // Optional column (migration 00023) — tolerate a host whose
                // schema is behind, same as schedule_id on filter rules.
                TableId = SafeNullableGuid(reader, "table_id"),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at"))
            });
        }

        return list;
    }

    #endregion

    #region Filter Rule Operations

    public async Task<IReadOnlyList<FwFilterRule>> GetFilterRulesAsync(string? chain = null, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        var sql = "SELECT * FROM fw_filter_rules";
        if (chain != null) sql += " WHERE chain = @chain";
        sql += " ORDER BY chain, priority, created_at";

        await using var cmd = new NpgsqlCommand(sql, conn);
        if (chain != null) cmd.Parameters.AddWithValue("chain", chain);

        return await ReadFilterRulesAsync(cmd, ct);
    }

    public async Task<FwFilterRule?> GetFilterRuleByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "SELECT * FROM fw_filter_rules WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var results = await ReadFilterRulesAsync(cmd, ct);
        return results.FirstOrDefault();
    }

    public async Task<FwFilterRule> CreateFilterRuleAsync(FwFilterRule rule, CancellationToken ct = default)
    {
        GuardAgainstDefaultDenyBypass(rule);

        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        rule.Id = Guid.NewGuid();
        rule.CreatedAt = DateTime.UtcNow;

        const string sql = @"
            INSERT INTO fw_filter_rules (id, chain, description, action, protocol, interface_in_id, interface_out_id,
                source_addresses, destination_addresses, destination_ports, connection_state, rate_limit, log_prefix,
                enabled, priority, schedule_id, schedule_invert, created_at)
            VALUES (@id, @chain, @desc, @action, @proto, @ifin, @ifout, @src, @dst, @ports, @state, @rate, @log, @enabled, @priority, @sched, @invert, @created)";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddFilterRuleParams(cmd, rule);

        await cmd.ExecuteNonQueryAsync(ct);
        await ScheduleApplyNotify.TrySendAsync(conn, $"filter.create:{rule.Id:N}", _logger, ct);

        await LogAuditAsync("fw_filter_rules", rule.Id, "INSERT", null, rule, null, ct);

        _logger.LogInformation("Created filter rule: {Desc}", rule.Description ?? rule.Action);
        return rule;
    }

    public async Task<FwFilterRule> UpdateFilterRuleAsync(FwFilterRule rule, CancellationToken ct = default)
    {
        GuardAgainstDefaultDenyBypass(rule);

        var existing = await GetFilterRuleByIdAsync(rule.Id, ct);

        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = @"
            UPDATE fw_filter_rules
            SET chain = @chain, description = @desc, action = @action, protocol = @proto,
                interface_in_id = @ifin, interface_out_id = @ifout, source_addresses = @src,
                destination_addresses = @dst, destination_ports = @ports, connection_state = @state,
                rate_limit = @rate, log_prefix = @log, enabled = @enabled, priority = @priority,
                schedule_id = @sched, schedule_invert = @invert
            WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddFilterRuleParams(cmd, rule);

        await cmd.ExecuteNonQueryAsync(ct);
        await ScheduleApplyNotify.TrySendAsync(conn, $"filter.update:{rule.Id:N}", _logger, ct);

        await LogAuditAsync("fw_filter_rules", rule.Id, "UPDATE", existing, rule, null, ct);

        return rule;
    }

    /// <inheritdoc />
    public async Task<string> PreviewFilterRuleAsync(FwFilterRule rule, CancellationToken ct = default)
    {
        var interfaces = await GetInterfacesAsync(ct);
        var ifaceMap = interfaces.ToDictionary(i => i.Id, i => i.Name);

        // Same resolution the generator does: network-object and service names
        // become literal CIDRs and ports. Mutates the throwaway rule only.
        await ResolveAddressesAsync(new[] { rule }, ct);

        return GenerateFilterRule(rule, ifaceMap).Trim();
    }

    /// <summary>
    /// Refuse to store an enabled filter rule that would make its chain's
    /// default-deny policy unreachable — an accept with no interface, no
    /// address, no port and a state match that still admits new connections.
    /// See <see cref="FwFilterRuleGuard"/> for the incident this prevents.
    ///
    /// Throws rather than returning a flag: the callers are the Web's save
    /// action and the API, both of which already turn an exception into a
    /// failed <c>ServiceResponse</c> carrying this message to the operator.
    /// </summary>
    private void GuardAgainstDefaultDenyBypass(FwFilterRule rule)
    {
        if (FwFilterRuleGuard.DescribeBypass(rule) is not { } reason) return;

        _logger.LogWarning("Rejected filter rule {Description}: {Reason}",
            rule.Description ?? rule.Action, reason);
        throw new InvalidOperationException(reason);
    }

    public async Task<bool> DeleteFilterRuleAsync(Guid id, CancellationToken ct = default)
    {
        var existing = await GetFilterRuleByIdAsync(id, ct);
        if (existing == null) return false;

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM fw_filter_rules WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var rows = await cmd.ExecuteNonQueryAsync(ct);

        if (rows > 0)
        {
            await ScheduleApplyNotify.TrySendAsync(conn, $"filter.delete:{id:N}", _logger, ct);
            await LogAuditAsync("fw_filter_rules", id, "DELETE", existing, null, null, ct);
        }

        return rows > 0;
    }

    private static void AddFilterRuleParams(NpgsqlCommand cmd, FwFilterRule rule)
    {
        cmd.Parameters.AddWithValue("id", rule.Id);
        cmd.Parameters.AddWithValue("chain", rule.Chain);
        cmd.Parameters.AddWithValue("desc", rule.Description ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("action", rule.Action);
        cmd.Parameters.AddWithValue("proto", rule.Protocol ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("ifin", rule.InterfaceInId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("ifout", rule.InterfaceOutId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("src", rule.SourceAddresses ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("dst", rule.DestinationAddresses ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("ports", rule.DestinationPorts ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("state", rule.ConnectionState ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("rate", rule.RateLimit ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("log", rule.LogPrefix ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("enabled", rule.Enabled);
        cmd.Parameters.AddWithValue("priority", rule.Priority);
        cmd.Parameters.AddWithValue("sched", (object?)rule.ScheduleId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("invert", rule.ScheduleInvert);
        cmd.Parameters.AddWithValue("created", rule.CreatedAt);
    }

    private static async Task<IReadOnlyList<FwFilterRule>> ReadFilterRulesAsync(NpgsqlCommand cmd, CancellationToken ct)
    {
        var list = new List<FwFilterRule>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            list.Add(new FwFilterRule
            {
                Id = reader.GetGuid(reader.GetOrdinal("id")),
                Chain = reader.GetString(reader.GetOrdinal("chain")),
                Description = reader.IsDBNull(reader.GetOrdinal("description")) ? null : reader.GetString(reader.GetOrdinal("description")),
                Action = reader.GetString(reader.GetOrdinal("action")),
                Protocol = reader.IsDBNull(reader.GetOrdinal("protocol")) ? null : reader.GetString(reader.GetOrdinal("protocol")),
                InterfaceInId = reader.IsDBNull(reader.GetOrdinal("interface_in_id")) ? null : reader.GetGuid(reader.GetOrdinal("interface_in_id")),
                InterfaceOutId = reader.IsDBNull(reader.GetOrdinal("interface_out_id")) ? null : reader.GetGuid(reader.GetOrdinal("interface_out_id")),
                SourceAddresses = reader.IsDBNull(reader.GetOrdinal("source_addresses")) ? null : reader.GetFieldValue<string[]>(reader.GetOrdinal("source_addresses")),
                DestinationAddresses = reader.IsDBNull(reader.GetOrdinal("destination_addresses")) ? null : reader.GetFieldValue<string[]>(reader.GetOrdinal("destination_addresses")),
                DestinationPorts = reader.IsDBNull(reader.GetOrdinal("destination_ports")) ? null : reader.GetFieldValue<string[]>(reader.GetOrdinal("destination_ports")),
                ConnectionState = reader.IsDBNull(reader.GetOrdinal("connection_state")) ? null : reader.GetFieldValue<string[]>(reader.GetOrdinal("connection_state")),
                RateLimit = reader.IsDBNull(reader.GetOrdinal("rate_limit")) ? null : reader.GetString(reader.GetOrdinal("rate_limit")),
                LogPrefix = reader.IsDBNull(reader.GetOrdinal("log_prefix")) ? null : reader.GetString(reader.GetOrdinal("log_prefix")),
                Enabled = reader.GetBoolean(reader.GetOrdinal("enabled")),
                Priority = reader.GetInt32(reader.GetOrdinal("priority")),
                ScheduleId = SafeNullableGuid(reader, "schedule_id"),
                ScheduleInvert = SafeBool(reader, "schedule_invert"),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at"))
            });
        }

        return list;
    }

    #endregion

    #region Port Forward Operations

    public async Task<IReadOnlyList<FwPortForward>> GetPortForwardsAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "SELECT * FROM fw_port_forwards ORDER BY priority, external_port_start";

        await using var cmd = new NpgsqlCommand(sql, conn);
        return await ReadPortForwardsAsync(cmd, ct);
    }

    public async Task<FwPortForward?> GetPortForwardByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "SELECT * FROM fw_port_forwards WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var results = await ReadPortForwardsAsync(cmd, ct);
        return results.FirstOrDefault();
    }

    public async Task<FwPortForward> CreatePortForwardAsync(FwPortForward pf, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        pf.Id = Guid.NewGuid();
        pf.CreatedAt = DateTime.UtcNow;

        const string sql = @"
            INSERT INTO fw_port_forwards (id, description, protocol, interface_id, source_addresses,
                external_port_start, external_port_end, internal_ip, internal_port, enabled, priority, created_at)
            VALUES (@id, @desc, @proto, @iface, @src, @extStart, @extEnd, @intIp, @intPort, @enabled, @priority, @created)";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddPortForwardParams(cmd, pf);

        await cmd.ExecuteNonQueryAsync(ct);

        await LogAuditAsync("fw_port_forwards", pf.Id, "INSERT", null, pf, null, ct);

        _logger.LogInformation("Created port forward: {Desc}", pf.Description ?? $"{pf.ExternalPortStart}->{pf.InternalIp}:{pf.InternalPort}");
        return pf;
    }

    public async Task<FwPortForward> UpdatePortForwardAsync(FwPortForward pf, CancellationToken ct = default)
    {
        var existing = await GetPortForwardByIdAsync(pf.Id, ct);

        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = @"
            UPDATE fw_port_forwards
            SET description = @desc, protocol = @proto, interface_id = @iface, source_addresses = @src,
                external_port_start = @extStart, external_port_end = @extEnd, internal_ip = @intIp,
                internal_port = @intPort, enabled = @enabled, priority = @priority
            WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddPortForwardParams(cmd, pf);

        await cmd.ExecuteNonQueryAsync(ct);

        await LogAuditAsync("fw_port_forwards", pf.Id, "UPDATE", existing, pf, null, ct);

        return pf;
    }

    public async Task<bool> DeletePortForwardAsync(Guid id, CancellationToken ct = default)
    {
        var existing = await GetPortForwardByIdAsync(id, ct);
        if (existing == null) return false;

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM fw_port_forwards WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var rows = await cmd.ExecuteNonQueryAsync(ct);

        if (rows > 0)
        {
            await LogAuditAsync("fw_port_forwards", id, "DELETE", existing, null, null, ct);
        }

        return rows > 0;
    }

    private static void AddPortForwardParams(NpgsqlCommand cmd, FwPortForward pf)
    {
        cmd.Parameters.AddWithValue("id", pf.Id);
        cmd.Parameters.AddWithValue("desc", pf.Description ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("proto", pf.Protocol);
        cmd.Parameters.AddWithValue("iface", pf.InterfaceId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("src", pf.SourceAddresses ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("extStart", pf.ExternalPortStart);
        cmd.Parameters.AddWithValue("extEnd", pf.ExternalPortEnd ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("intIp", pf.InternalIp);
        cmd.Parameters.AddWithValue("intPort", pf.InternalPort);
        cmd.Parameters.AddWithValue("enabled", pf.Enabled);
        cmd.Parameters.AddWithValue("priority", pf.Priority);
        cmd.Parameters.AddWithValue("created", pf.CreatedAt);
    }

    private static async Task<IReadOnlyList<FwPortForward>> ReadPortForwardsAsync(NpgsqlCommand cmd, CancellationToken ct)
    {
        var list = new List<FwPortForward>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            list.Add(new FwPortForward
            {
                Id = reader.GetGuid(reader.GetOrdinal("id")),
                Description = reader.IsDBNull(reader.GetOrdinal("description")) ? null : reader.GetString(reader.GetOrdinal("description")),
                Protocol = reader.GetString(reader.GetOrdinal("protocol")),
                InterfaceId = reader.IsDBNull(reader.GetOrdinal("interface_id")) ? null : reader.GetGuid(reader.GetOrdinal("interface_id")),
                SourceAddresses = reader.IsDBNull(reader.GetOrdinal("source_addresses")) ? null : reader.GetFieldValue<string[]>(reader.GetOrdinal("source_addresses")),
                ExternalPortStart = reader.GetInt32(reader.GetOrdinal("external_port_start")),
                ExternalPortEnd = reader.IsDBNull(reader.GetOrdinal("external_port_end")) ? null : reader.GetInt32(reader.GetOrdinal("external_port_end")),
                InternalIp = reader.GetFieldValue<System.Net.IPAddress>(reader.GetOrdinal("internal_ip")),
                InternalPort = reader.GetInt32(reader.GetOrdinal("internal_port")),
                Enabled = reader.GetBoolean(reader.GetOrdinal("enabled")),
                Priority = reader.GetInt32(reader.GetOrdinal("priority")),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at"))
            });
        }

        return list;
    }

    #endregion

    #region NAT Rule Operations

    public async Task<IReadOnlyList<FwNatRule>> GetNatRulesAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        // Cast cidr → text so Npgsql 10 hands us a System.String for source_network
        // (the model is string). Without the cast, GetString throws.
        const string sql = @"
            SELECT id, type, description, source_network::text AS source_network, output_interface_id,
                   snat_address, enabled, priority, created_at
            FROM fw_nat_rules ORDER BY priority, type";

        await using var cmd = new NpgsqlCommand(sql, conn);
        return await ReadNatRulesAsync(cmd, ct);
    }

    public async Task<FwNatRule?> GetNatRuleByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = @"
            SELECT id, type, description, source_network::text AS source_network, output_interface_id,
                   snat_address, enabled, priority, created_at
            FROM fw_nat_rules WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var results = await ReadNatRulesAsync(cmd, ct);
        return results.FirstOrDefault();
    }

    public async Task<FwNatRule> CreateNatRuleAsync(FwNatRule rule, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        rule.Id = Guid.NewGuid();
        rule.CreatedAt = DateTime.UtcNow;

        // Postgres won't auto-cast text → cidr, so we cast inside the SQL.
        // Same shape used in UpdateNatRuleAsync below.
        const string sql = @"
            INSERT INTO fw_nat_rules (id, type, description, source_network, output_interface_id, snat_address, enabled, priority, created_at)
            VALUES (@id, @type, @desc, @src::cidr, @iface, @snat, @enabled, @priority, @created)";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddNatRuleParams(cmd, rule);

        await cmd.ExecuteNonQueryAsync(ct);

        await LogAuditAsync("fw_nat_rules", rule.Id, "INSERT", null, rule, null, ct);

        _logger.LogInformation("Created NAT rule: {Type} {Desc}", rule.Type, rule.Description);
        return rule;
    }

    public async Task<FwNatRule> UpdateNatRuleAsync(FwNatRule rule, CancellationToken ct = default)
    {
        var existing = await GetNatRuleByIdAsync(rule.Id, ct);

        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = @"
            UPDATE fw_nat_rules
            SET type = @type, description = @desc, source_network = @src::cidr, output_interface_id = @iface,
                snat_address = @snat, enabled = @enabled, priority = @priority
            WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddNatRuleParams(cmd, rule);

        await cmd.ExecuteNonQueryAsync(ct);

        await LogAuditAsync("fw_nat_rules", rule.Id, "UPDATE", existing, rule, null, ct);

        return rule;
    }

    public async Task<bool> DeleteNatRuleAsync(Guid id, CancellationToken ct = default)
    {
        var existing = await GetNatRuleByIdAsync(id, ct);
        if (existing == null) return false;

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM fw_nat_rules WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var rows = await cmd.ExecuteNonQueryAsync(ct);

        if (rows > 0)
        {
            await LogAuditAsync("fw_nat_rules", id, "DELETE", existing, null, null, ct);
        }

        return rows > 0;
    }

    private static void AddNatRuleParams(NpgsqlCommand cmd, FwNatRule rule)
    {
        cmd.Parameters.AddWithValue("id", rule.Id);
        cmd.Parameters.AddWithValue("type", rule.Type);
        cmd.Parameters.AddWithValue("desc", rule.Description ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("src", rule.SourceNetwork);
        cmd.Parameters.AddWithValue("iface", rule.OutputInterfaceId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("snat", rule.SnatAddress ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("enabled", rule.Enabled);
        cmd.Parameters.AddWithValue("priority", rule.Priority);
        cmd.Parameters.AddWithValue("created", rule.CreatedAt);
    }

    private static async Task<IReadOnlyList<FwNatRule>> ReadNatRulesAsync(NpgsqlCommand cmd, CancellationToken ct)
    {
        var list = new List<FwNatRule>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            list.Add(new FwNatRule
            {
                Id = reader.GetGuid(reader.GetOrdinal("id")),
                Type = reader.GetString(reader.GetOrdinal("type")),
                Description = reader.IsDBNull(reader.GetOrdinal("description")) ? null : reader.GetString(reader.GetOrdinal("description")),
                SourceNetwork = reader.GetString(reader.GetOrdinal("source_network")),
                OutputInterfaceId = reader.IsDBNull(reader.GetOrdinal("output_interface_id")) ? null : reader.GetGuid(reader.GetOrdinal("output_interface_id")),
                SnatAddress = reader.IsDBNull(reader.GetOrdinal("snat_address")) ? null : reader.GetFieldValue<System.Net.IPAddress>(reader.GetOrdinal("snat_address")),
                Enabled = reader.GetBoolean(reader.GetOrdinal("enabled")),
                Priority = reader.GetInt32(reader.GetOrdinal("priority")),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at"))
            });
        }

        return list;
    }

    #endregion

    #region Traffic Mark Operations

    public async Task<IReadOnlyList<FwTrafficMark>> GetTrafficMarksAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "SELECT * FROM fw_traffic_marks ORDER BY mark_value";

        await using var cmd = new NpgsqlCommand(sql, conn);
        return await ReadTrafficMarksAsync(cmd, ct);
    }

    public async Task<FwTrafficMark?> GetTrafficMarkByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "SELECT * FROM fw_traffic_marks WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var results = await ReadTrafficMarksAsync(cmd, ct);
        return results.FirstOrDefault();
    }

    public async Task<FwTrafficMark> CreateTrafficMarkAsync(FwTrafficMark mark, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        mark.Id = Guid.NewGuid();
        mark.CreatedAt = DateTime.UtcNow;

        const string sql = @"
            INSERT INTO fw_traffic_marks (id, name, mark_value, description, route_table, created_at)
            VALUES (@id, @name, @value, @desc, @table, @created)";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", mark.Id);
        cmd.Parameters.AddWithValue("name", mark.Name);
        cmd.Parameters.AddWithValue("value", mark.MarkValue);
        cmd.Parameters.AddWithValue("desc", mark.Description ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("table", mark.RouteTable ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("created", mark.CreatedAt);

        await cmd.ExecuteNonQueryAsync(ct);

        await LogAuditAsync("fw_traffic_marks", mark.Id, "INSERT", null, mark, null, ct);

        return mark;
    }

    public async Task<FwTrafficMark> UpdateTrafficMarkAsync(FwTrafficMark mark, CancellationToken ct = default)
    {
        var existing = await GetTrafficMarkByIdAsync(mark.Id, ct);

        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = @"
            UPDATE fw_traffic_marks
            SET name = @name, mark_value = @value, description = @desc, route_table = @table
            WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", mark.Id);
        cmd.Parameters.AddWithValue("name", mark.Name);
        cmd.Parameters.AddWithValue("value", mark.MarkValue);
        cmd.Parameters.AddWithValue("desc", mark.Description ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("table", mark.RouteTable ?? (object)DBNull.Value);

        await cmd.ExecuteNonQueryAsync(ct);

        await LogAuditAsync("fw_traffic_marks", mark.Id, "UPDATE", existing, mark, null, ct);

        return mark;
    }

    public async Task<bool> DeleteTrafficMarkAsync(Guid id, CancellationToken ct = default)
    {
        var existing = await GetTrafficMarkByIdAsync(id, ct);
        if (existing == null) return false;

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM fw_traffic_marks WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var rows = await cmd.ExecuteNonQueryAsync(ct);

        if (rows > 0)
        {
            await LogAuditAsync("fw_traffic_marks", id, "DELETE", existing, null, null, ct);
        }

        return rows > 0;
    }

    private static async Task<IReadOnlyList<FwTrafficMark>> ReadTrafficMarksAsync(NpgsqlCommand cmd, CancellationToken ct)
    {
        var list = new List<FwTrafficMark>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            list.Add(new FwTrafficMark
            {
                Id = reader.GetGuid(reader.GetOrdinal("id")),
                Name = reader.GetString(reader.GetOrdinal("name")),
                MarkValue = reader.GetInt32(reader.GetOrdinal("mark_value")),
                Description = reader.IsDBNull(reader.GetOrdinal("description")) ? null : reader.GetString(reader.GetOrdinal("description")),
                RouteTable = reader.IsDBNull(reader.GetOrdinal("route_table")) ? null : reader.GetString(reader.GetOrdinal("route_table")),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at"))
            });
        }

        return list;
    }

    #endregion

    #region Mangle Rule Operations

    public async Task<IReadOnlyList<FwMangleRule>> GetMangleRulesAsync(string? chain = null, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        var sql = "SELECT * FROM fw_mangle_rules";
        if (chain != null) sql += " WHERE chain = @chain";
        sql += " ORDER BY chain, priority";

        await using var cmd = new NpgsqlCommand(sql, conn);
        if (chain != null) cmd.Parameters.AddWithValue("chain", chain);

        return await ReadMangleRulesAsync(cmd, ct);
    }

    public async Task<FwMangleRule?> GetMangleRuleByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "SELECT * FROM fw_mangle_rules WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var results = await ReadMangleRulesAsync(cmd, ct);
        return results.FirstOrDefault();
    }

    public async Task<FwMangleRule> CreateMangleRuleAsync(FwMangleRule rule, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        rule.Id = Guid.NewGuid();
        rule.CreatedAt = DateTime.UtcNow;

        const string sql = @"
            INSERT INTO fw_mangle_rules (id, chain, description, mark_id, protocol, source_addresses,
                destination_addresses, destination_ports, enabled, priority, created_at)
            VALUES (@id, @chain, @desc, @mark, @proto, @src, @dst, @ports, @enabled, @priority, @created)";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddMangleRuleParams(cmd, rule);

        await cmd.ExecuteNonQueryAsync(ct);

        await LogAuditAsync("fw_mangle_rules", rule.Id, "INSERT", null, rule, null, ct);

        return rule;
    }

    public async Task<FwMangleRule> UpdateMangleRuleAsync(FwMangleRule rule, CancellationToken ct = default)
    {
        var existing = await GetMangleRuleByIdAsync(rule.Id, ct);

        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = @"
            UPDATE fw_mangle_rules
            SET chain = @chain, description = @desc, mark_id = @mark, protocol = @proto,
                source_addresses = @src, destination_addresses = @dst, destination_ports = @ports,
                enabled = @enabled, priority = @priority
            WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddMangleRuleParams(cmd, rule);

        await cmd.ExecuteNonQueryAsync(ct);

        await LogAuditAsync("fw_mangle_rules", rule.Id, "UPDATE", existing, rule, null, ct);

        return rule;
    }

    public async Task<bool> DeleteMangleRuleAsync(Guid id, CancellationToken ct = default)
    {
        var existing = await GetMangleRuleByIdAsync(id, ct);
        if (existing == null) return false;

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM fw_mangle_rules WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var rows = await cmd.ExecuteNonQueryAsync(ct);

        if (rows > 0)
        {
            await LogAuditAsync("fw_mangle_rules", id, "DELETE", existing, null, null, ct);
        }

        return rows > 0;
    }

    private static void AddMangleRuleParams(NpgsqlCommand cmd, FwMangleRule rule)
    {
        cmd.Parameters.AddWithValue("id", rule.Id);
        cmd.Parameters.AddWithValue("chain", rule.Chain);
        cmd.Parameters.AddWithValue("desc", rule.Description ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("mark", rule.MarkId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("proto", rule.Protocol ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("src", rule.SourceAddresses ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("dst", rule.DestinationAddresses ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("ports", rule.DestinationPorts ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("enabled", rule.Enabled);
        cmd.Parameters.AddWithValue("priority", rule.Priority);
        cmd.Parameters.AddWithValue("created", rule.CreatedAt);
    }

    private static async Task<IReadOnlyList<FwMangleRule>> ReadMangleRulesAsync(NpgsqlCommand cmd, CancellationToken ct)
    {
        var list = new List<FwMangleRule>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            list.Add(new FwMangleRule
            {
                Id = reader.GetGuid(reader.GetOrdinal("id")),
                Chain = reader.GetString(reader.GetOrdinal("chain")),
                Description = reader.IsDBNull(reader.GetOrdinal("description")) ? null : reader.GetString(reader.GetOrdinal("description")),
                MarkId = reader.IsDBNull(reader.GetOrdinal("mark_id")) ? null : reader.GetGuid(reader.GetOrdinal("mark_id")),
                Protocol = reader.IsDBNull(reader.GetOrdinal("protocol")) ? null : reader.GetString(reader.GetOrdinal("protocol")),
                SourceAddresses = reader.IsDBNull(reader.GetOrdinal("source_addresses")) ? null : reader.GetFieldValue<string[]>(reader.GetOrdinal("source_addresses")),
                DestinationAddresses = reader.IsDBNull(reader.GetOrdinal("destination_addresses")) ? null : reader.GetFieldValue<string[]>(reader.GetOrdinal("destination_addresses")),
                DestinationPorts = reader.IsDBNull(reader.GetOrdinal("destination_ports")) ? null : reader.GetFieldValue<string[]>(reader.GetOrdinal("destination_ports")),
                Enabled = reader.GetBoolean(reader.GetOrdinal("enabled")),
                Priority = reader.GetInt32(reader.GetOrdinal("priority")),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at"))
            });
        }

        return list;
    }

    #endregion

    #region QoS Operations

    public async Task<IReadOnlyList<FwQosConfig>> GetQosConfigsAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "SELECT * FROM fw_qos_config ORDER BY created_at";

        await using var cmd = new NpgsqlCommand(sql, conn);
        var list = new List<FwQosConfig>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            list.Add(new FwQosConfig
            {
                Id = reader.GetGuid(reader.GetOrdinal("id")),
                InterfaceId = reader.IsDBNull(reader.GetOrdinal("interface_id")) ? null : reader.GetGuid(reader.GetOrdinal("interface_id")),
                Enabled = reader.GetBoolean(reader.GetOrdinal("enabled")),
                TotalBandwidthMbps = reader.GetInt32(reader.GetOrdinal("total_bandwidth_mbps")),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at"))
            });
        }

        return list;
    }

    public async Task<FwQosConfig?> GetQosConfigByIdAsync(Guid id, CancellationToken ct = default)
    {
        var configs = await GetQosConfigsAsync(ct);
        return configs.FirstOrDefault(c => c.Id == id);
    }

    public async Task<FwQosConfig> CreateQosConfigAsync(FwQosConfig config, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        config.Id = Guid.NewGuid();
        config.CreatedAt = DateTime.UtcNow;

        const string sql = @"
            INSERT INTO fw_qos_config (id, interface_id, enabled, total_bandwidth_mbps, created_at)
            VALUES (@id, @iface, @enabled, @bw, @created)";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", config.Id);
        cmd.Parameters.AddWithValue("iface", config.InterfaceId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("enabled", config.Enabled);
        cmd.Parameters.AddWithValue("bw", config.TotalBandwidthMbps);
        cmd.Parameters.AddWithValue("created", config.CreatedAt);

        await cmd.ExecuteNonQueryAsync(ct);

        await LogAuditAsync("fw_qos_config", config.Id, "INSERT", null, config, null, ct);

        return config;
    }

    public async Task<FwQosConfig> UpdateQosConfigAsync(FwQosConfig config, CancellationToken ct = default)
    {
        var existing = await GetQosConfigByIdAsync(config.Id, ct);

        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = @"
            UPDATE fw_qos_config
            SET interface_id = @iface, enabled = @enabled, total_bandwidth_mbps = @bw
            WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", config.Id);
        cmd.Parameters.AddWithValue("iface", config.InterfaceId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("enabled", config.Enabled);
        cmd.Parameters.AddWithValue("bw", config.TotalBandwidthMbps);

        await cmd.ExecuteNonQueryAsync(ct);

        await LogAuditAsync("fw_qos_config", config.Id, "UPDATE", existing, config, null, ct);

        return config;
    }

    public async Task<bool> DeleteQosConfigAsync(Guid id, CancellationToken ct = default)
    {
        var existing = await GetQosConfigByIdAsync(id, ct);
        if (existing == null) return false;

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM fw_qos_config WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        var rows = await cmd.ExecuteNonQueryAsync(ct);

        if (rows > 0)
        {
            await LogAuditAsync("fw_qos_config", id, "DELETE", existing, null, null, ct);
        }

        return rows > 0;
    }

    public async Task<IReadOnlyList<FwQosClass>> GetQosClassesAsync(Guid? configId = null, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        var sql = "SELECT * FROM fw_qos_classes";
        if (configId.HasValue) sql += " WHERE qos_config_id = @configId";
        sql += " ORDER BY priority";

        await using var cmd = new NpgsqlCommand(sql, conn);
        if (configId.HasValue) cmd.Parameters.AddWithValue("configId", configId.Value);

        var list = new List<FwQosClass>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            list.Add(new FwQosClass
            {
                Id = reader.GetGuid(reader.GetOrdinal("id")),
                QosConfigId = reader.IsDBNull(reader.GetOrdinal("qos_config_id")) ? null : reader.GetGuid(reader.GetOrdinal("qos_config_id")),
                Name = reader.GetString(reader.GetOrdinal("name")),
                MarkId = reader.IsDBNull(reader.GetOrdinal("mark_id")) ? null : reader.GetGuid(reader.GetOrdinal("mark_id")),
                GuaranteedMbps = reader.GetInt32(reader.GetOrdinal("guaranteed_mbps")),
                CeilingMbps = reader.GetInt32(reader.GetOrdinal("ceiling_mbps")),
                Priority = reader.GetInt32(reader.GetOrdinal("priority")),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at"))
            });
        }

        return list;
    }

    public async Task<FwQosClass> CreateQosClassAsync(FwQosClass qosClass, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        qosClass.Id = Guid.NewGuid();
        qosClass.CreatedAt = DateTime.UtcNow;

        const string sql = @"
            INSERT INTO fw_qos_classes (id, qos_config_id, name, mark_id, guaranteed_mbps, ceiling_mbps, priority, created_at)
            VALUES (@id, @config, @name, @mark, @guaranteed, @ceiling, @priority, @created)";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", qosClass.Id);
        cmd.Parameters.AddWithValue("config", qosClass.QosConfigId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("name", qosClass.Name);
        cmd.Parameters.AddWithValue("mark", qosClass.MarkId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("guaranteed", qosClass.GuaranteedMbps);
        cmd.Parameters.AddWithValue("ceiling", qosClass.CeilingMbps);
        cmd.Parameters.AddWithValue("priority", qosClass.Priority);
        cmd.Parameters.AddWithValue("created", qosClass.CreatedAt);

        await cmd.ExecuteNonQueryAsync(ct);

        await LogAuditAsync("fw_qos_classes", qosClass.Id, "INSERT", null, qosClass, null, ct);

        return qosClass;
    }

    public async Task<FwQosClass> UpdateQosClassAsync(FwQosClass qosClass, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = @"
            UPDATE fw_qos_classes
            SET qos_config_id = @config, name = @name, mark_id = @mark,
                guaranteed_mbps = @guaranteed, ceiling_mbps = @ceiling, priority = @priority
            WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", qosClass.Id);
        cmd.Parameters.AddWithValue("config", qosClass.QosConfigId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("name", qosClass.Name);
        cmd.Parameters.AddWithValue("mark", qosClass.MarkId ?? (object)DBNull.Value);
        cmd.Parameters.AddWithValue("guaranteed", qosClass.GuaranteedMbps);
        cmd.Parameters.AddWithValue("ceiling", qosClass.CeilingMbps);
        cmd.Parameters.AddWithValue("priority", qosClass.Priority);

        await cmd.ExecuteNonQueryAsync(ct);

        return qosClass;
    }

    public async Task<bool> DeleteQosClassAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "DELETE FROM fw_qos_classes WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        return await cmd.ExecuteNonQueryAsync(ct) > 0;
    }

    #endregion

    #region Audit Log

    public Task<IReadOnlyList<FwAuditLog>> SearchAuditLogsAsync(
        string? tableName = null,
        string? action = null,
        DateTime? since = null,
        int limit = 100,
        int offset = 0,
        CancellationToken ct = default)
        => RunAuditQueryAsync(tableName, action, since, limit, offset, ct);

    public async Task<IReadOnlyList<string>> GetAuditTableNamesAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "SELECT DISTINCT table_name FROM fw_audit_log ORDER BY table_name", conn);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var list = new List<string>();
        while (await reader.ReadAsync(ct)) list.Add(reader.GetString(0));
        return list;
    }

    private async Task<IReadOnlyList<FwAuditLog>> RunAuditQueryAsync(
        string? tableName, string? action, DateTime? since, int limit, int offset, CancellationToken ct)
    {
        var where = new List<string>();
        if (!string.IsNullOrEmpty(tableName)) where.Add("table_name = @table");
        if (!string.IsNullOrEmpty(action))    where.Add("action = @action");
        if (since.HasValue)                    where.Add("created_at >= @since");
        var whereClause = where.Count == 0 ? "" : "WHERE " + string.Join(" AND ", where);
        var sql = $"SELECT * FROM fw_audit_log {whereClause} ORDER BY created_at DESC LIMIT @limit OFFSET @offset";

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        if (!string.IsNullOrEmpty(tableName)) cmd.Parameters.AddWithValue("table",  tableName);
        if (!string.IsNullOrEmpty(action))    cmd.Parameters.AddWithValue("action", action);
        if (since.HasValue)                    cmd.Parameters.AddWithValue("since",  since.Value);
        cmd.Parameters.AddWithValue("limit", limit);
        cmd.Parameters.AddWithValue("offset", offset);

        var list = new List<FwAuditLog>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            list.Add(new FwAuditLog
            {
                Id = reader.GetGuid(reader.GetOrdinal("id")),
                TableName = reader.GetString(reader.GetOrdinal("table_name")),
                RecordId = reader.GetGuid(reader.GetOrdinal("record_id")),
                Action = reader.GetString(reader.GetOrdinal("action")),
                OldValues = reader.IsDBNull(reader.GetOrdinal("old_values")) ? null : reader.GetString(reader.GetOrdinal("old_values")),
                NewValues = reader.IsDBNull(reader.GetOrdinal("new_values")) ? null : reader.GetString(reader.GetOrdinal("new_values")),
                UserId = reader.IsDBNull(reader.GetOrdinal("user_id")) ? null : reader.GetString(reader.GetOrdinal("user_id")),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at"))
            });
        }
        return list;
    }

    public async Task<IReadOnlyList<FwAuditLog>> GetAuditLogsAsync(int limit = 100, int offset = 0, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "SELECT * FROM fw_audit_log ORDER BY created_at DESC LIMIT @limit OFFSET @offset";

        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("limit", limit);
        cmd.Parameters.AddWithValue("offset", offset);

        var list = new List<FwAuditLog>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        while (await reader.ReadAsync(ct))
        {
            list.Add(new FwAuditLog
            {
                Id = reader.GetGuid(reader.GetOrdinal("id")),
                TableName = reader.GetString(reader.GetOrdinal("table_name")),
                RecordId = reader.GetGuid(reader.GetOrdinal("record_id")),
                Action = reader.GetString(reader.GetOrdinal("action")),
                OldValues = reader.IsDBNull(reader.GetOrdinal("old_values")) ? null : reader.GetString(reader.GetOrdinal("old_values")),
                NewValues = reader.IsDBNull(reader.GetOrdinal("new_values")) ? null : reader.GetString(reader.GetOrdinal("new_values")),
                UserId = reader.IsDBNull(reader.GetOrdinal("user_id")) ? null : reader.GetString(reader.GetOrdinal("user_id")),
                CreatedAt = reader.GetDateTime(reader.GetOrdinal("created_at"))
            });
        }

        return list;
    }

    public async Task LogAuditAsync(string tableName, Guid recordId, string action, object? oldValues, object? newValues, string? userId = null, CancellationToken ct = default)
    {
        try
        {
            await using var conn = await _dataSource.OpenConnectionAsync(ct);

            const string sql = @"
                INSERT INTO fw_audit_log (id, table_name, record_id, action, old_values, new_values, user_id, created_at)
                VALUES (@id, @table, @record, @action, @old::jsonb, @new::jsonb, @user, @created)";

            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("id", Guid.NewGuid());
            cmd.Parameters.AddWithValue("table", tableName);
            cmd.Parameters.AddWithValue("record", recordId);
            cmd.Parameters.AddWithValue("action", action);
            cmd.Parameters.AddWithValue("old", oldValues != null ? JsonSerializer.Serialize(oldValues, AuditJsonOptions) : DBNull.Value);
            cmd.Parameters.AddWithValue("new", newValues != null ? JsonSerializer.Serialize(newValues, AuditJsonOptions) : DBNull.Value);
            cmd.Parameters.AddWithValue("user", userId ?? (object)DBNull.Value);
            cmd.Parameters.AddWithValue("created", DateTime.UtcNow);

            await cmd.ExecuteNonQueryAsync(ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to log audit entry for {Table}.{Action}", tableName, action);
        }
    }

    #endregion

    #region Statistics

    public async Task<FirewallStats> GetStatsAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = @"
            SELECT
                (SELECT COUNT(*) FROM fw_interfaces) as total_interfaces,
                (SELECT COUNT(*) FROM fw_interfaces WHERE enabled = true) as active_interfaces,
                (SELECT COUNT(*) FROM fw_filter_rules) as total_filter_rules,
                (SELECT COUNT(*) FROM fw_filter_rules WHERE enabled = true) as enabled_filter_rules,
                (SELECT COUNT(*) FROM fw_port_forwards) as total_port_forwards,
                (SELECT COUNT(*) FROM fw_port_forwards WHERE enabled = true) as enabled_port_forwards,
                (SELECT COUNT(*) FROM fw_nat_rules) as total_nat_rules,
                (SELECT COUNT(*) FROM fw_nat_rules WHERE enabled = true) as enabled_nat_rules";

        await using var cmd = new NpgsqlCommand(sql, conn);
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        if (await reader.ReadAsync(ct))
        {
            return new FirewallStats
            {
                TotalInterfaces = reader.GetInt32(0),
                ActiveInterfaces = reader.GetInt32(1),
                TotalFilterRules = reader.GetInt32(2),
                EnabledFilterRules = reader.GetInt32(3),
                TotalPortForwards = reader.GetInt32(4),
                EnabledPortForwards = reader.GetInt32(5),
                TotalNatRules = reader.GetInt32(6),
                EnabledNatRules = reader.GetInt32(7)
            };
        }

        return new FirewallStats();
    }

    #endregion

    #region nftables Configuration Generation

    public Task<string> GenerateNftablesConfigPreviewAsync(CancellationToken ct = default)
    {
        return GenerateNftablesConfigAsync(ct);
    }

    public async Task<string> GenerateNftablesConfigAsync(CancellationToken ct = default)
    {
        var sb = new StringBuilder();

        // Header
        sb.AppendLine("#!/usr/sbin/nft -f");
        sb.AppendLine("# NetFirewall nftables configuration");
        sb.AppendLine($"# Generated: {DateTime.UtcNow:O}");
        sb.AppendLine();

        // Flush existing rules
        sb.AppendLine("flush ruleset");
        sb.AppendLine();

        // Load data
        var interfaces = await GetInterfacesAsync(ct);
        var filterRules = await GetFilterRulesAsync(null, ct);
        var portForwards = await GetPortForwardsAsync(ct);
        var natRules = await GetNatRulesAsync(ct);
        var mangleRules = await GetMangleRulesAsync(null, ct);
        var trafficMarks = await GetTrafficMarksAsync(ct);
        var schedules = await GetSchedulesForGenerationAsync(ct);
        var wanIngressMarks = await GetWanIngressMarksAsync(ct);

        // Create interface name lookup
        var ifaceMap = interfaces.ToDictionary(i => i.Id, i => i.Name);
        var markMap = trafficMarks.ToDictionary(m => m.Id, m => m);
        var scheduleMap = schedules.ToDictionary(s => s.Id, s => s);

        // Schedule predicate: a null ScheduleId is always-on; otherwise the
        // referenced schedule must be active right now (in its own timezone).
        // This is what makes time-based rules work — the daemon's watcher
        // re-applies on transition so the snapshot stays fresh.
        var nowUtc = DateTimeOffset.UtcNow;
        bool RuleActiveNow(FwFilterRule r)
        {
            var isTimeLimit = string.Equals(
                r.LogPrefix, FwFilterRule.TimeLimitLogPrefix, StringComparison.Ordinal);

            // TIME-LIMIT drops are the schedule. After ON DELETE SET NULL they
            // would become 24/7 blocks — skip orphans (no schedule, or the
            // row the FK pointed at is gone).
            if (isTimeLimit &&
                (r.ScheduleId is null || !scheduleMap.ContainsKey(r.ScheduleId.Value)))
                return false;

            if (!r.ScheduleId.HasValue) return true;
            if (!scheduleMap.TryGetValue(r.ScheduleId.Value, out var s))
                return false;
            var live = s.IsActiveAt(nowUtc);
            return r.ScheduleInvert ? !live : live;
        }

        // Resolve named network objects in source/destination of every rule
        // BEFORE generators stringify them. We mutate the in-memory copies
        // (these are throwaway DTOs from this read, never persisted back).
        await ResolveAddressesAsync(filterRules,  ct);
        await ResolveAddressesAsync(portForwards, ct);
        await ResolveAddressesAsync(mangleRules,  ct);

        // NAT resolution returns a per-rule list because a single SourceNetwork
        // referencing a group can expand to N CIDRs, and SNAT/MASQUERADE in
        // nft only accepts one saddr per rule — we emit N rules.
        var natSources = await ResolveNatSourcesAsync(natRules, ct);

        // NAT table (for port forwards and masquerade/snat)
        sb.AppendLine("table ip nat {");
        sb.AppendLine("    chain prerouting {");
        sb.AppendLine("        type nat hook prerouting priority dstnat; policy accept;");

        // Port forwards (DNAT)
        foreach (var pf in portForwards.Where(p => p.Enabled))
        {
            var line = GeneratePortForwardRule(pf, ifaceMap);
            if (line is null)
            {
                sb.AppendLine($"        # SKIP port-forward {pf.Id} — incomplete (protocol/port/target missing)");
                continue;
            }
            sb.AppendLine(line);
        }

        sb.AppendLine("    }");
        sb.AppendLine();
        sb.AppendLine("    chain postrouting {");
        sb.AppendLine("        type nat hook postrouting priority srcnat; policy accept;");

        // NAT rules (masquerade/snat) — emit one nft rule per resolved source CIDR.
        foreach (var nat in natRules.Where(n => n.Enabled))
        {
            if (!natSources.TryGetValue(nat.Id, out var sources) || sources.Count == 0)
            {
                // Unresolvable source — skip with a comment so apply diff is honest.
                sb.AppendLine($"        # SKIP nat {nat.Id} — source '{nat.SourceNetwork}' could not be resolved");
                continue;
            }
            foreach (var src in sources)
            {
                var line = GenerateNatRule(nat, src, ifaceMap);
                if (line is null)
                {
                    sb.AppendLine($"        # SKIP nat {nat.Id} — unrenderable (unknown type, or snat without snat_address)");
                    continue;
                }
                sb.AppendLine(line);
            }
        }

        sb.AppendLine("    }");
        sb.AppendLine("}");
        sb.AppendLine();

        // Emit one filter chain, in priority order. Single place deciding what
        // reaches the ruleset, so the three chains can't drift apart.
        //
        // A rule the guard flags is SKIPPED, not emitted: an accept with no
        // interface, no address and no port matches everything and would shadow
        // every rule below it, leaving `policy drop` unreachable. Refusing it
        // here as well as on save means a row inserted straight into the DB
        // (a hand-written migration, a restored dump) can't silently open the
        // box either. Same fail-soft contract as the port-forward SKIPs below —
        // we drop the one bad rule, never the whole apply.
        void EmitFilterChain(string chain)
        {
            // First-match-wins: a second row that compiles to the same match +
            // verdict (e.g. three TIME-LIMIT drops for the same host) never
            // runs. Skip it so the live ruleset doesn't look like the schedule
            // was applied N times.
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var rule in filterRules
                         .Where(r => r.Enabled && r.Chain == chain && RuleActiveNow(r))
                         .OrderBy(r => r.Priority))
            {
                if (FwFilterRuleGuard.DescribeBypass(rule) is { } bypass)
                {
                    _logger.LogWarning("Skipped filter rule {Id} ({Description}) while generating the ruleset: {Reason}",
                        rule.Id, rule.Description ?? rule.Action, bypass);
                    sb.AppendLine($"        # SKIP filter rule {rule.Id} — default-deny bypass (accept with no interface/address/port)");
                    continue;
                }

                var line = GenerateFilterRule(rule, ifaceMap);
                if (!seen.Add(FilterLineDedupeKey(line)))
                {
                    _logger.LogInformation(
                        "Skipped filter rule {Id} ({Description}) — identical match already emitted in {Chain}",
                        rule.Id, rule.Description ?? rule.Action, chain);
                    continue;
                }

                sb.AppendLine(line);
            }
        }

        // Filter table
        sb.AppendLine("table ip filter {");

        // Input chain
        sb.AppendLine("    chain input {");
        sb.AppendLine("        type filter hook input priority filter; policy drop;");
        sb.AppendLine("        iif lo accept");

        EmitFilterChain("input");

        sb.AppendLine("    }");
        sb.AppendLine();

        // Forward chain
        sb.AppendLine("    chain forward {");
        sb.AppendLine("        type filter hook forward priority filter; policy drop;");

        EmitFilterChain("forward");

        sb.AppendLine("    }");
        sb.AppendLine();

        // Output chain
        sb.AppendLine("    chain output {");
        sb.AppendLine("        type filter hook output priority filter; policy accept;");

        EmitFilterChain("output");

        sb.AppendLine("    }");
        sb.AppendLine("}");
        sb.AppendLine();

        // Mangle table (for QoS marking, and dual-WAN inbound reply steering).
        //
        // Reply steering needs at least two WANs with DISTINCT marks: with one
        // WAN there is nothing to choose between, and with colliding marks the
        // policy routing itself is misconfigured and stamping can't help.
        var steerInboundReplies = wanIngressMarks
            .Select(w => w.Fwmark)
            .Distinct()
            .Count() >= 2;

        if (mangleRules.Any(m => m.Enabled) || steerInboundReplies)
        {
            sb.AppendLine("table ip mangle {");
            sb.AppendLine("    chain prerouting {");
            sb.AppendLine("        type filter hook prerouting priority mangle; policy accept;");

            if (steerInboundReplies)
            {
                sb.AppendLine("        # Dual-WAN inbound: remember which WAN a connection arrived on, and");
                sb.AppendLine("        # steer its replies back out the same one. Without this the");
                sb.AppendLine("        # LAN-default mark below sends every reply out the primary WAN while");
                sb.AppendLine("        # NAT restores the SECONDARY WAN's address as the source — the packet");
                sb.AppendLine("        # is dropped upstream and every DNAT'd service looks dead on the");
                sb.AppendLine("        # secondary WAN, even though the LAN host answered correctly.");
                sb.AppendLine("        #");
                sb.AppendLine("        # Only the REPLY direction is marked. Marking the inbound direction");
                sb.AppendLine("        # too would push WAN->LAN packets into the WAN routing table instead");
                sb.AppendLine("        # of delivering them to the LAN.");

                foreach (var (iface, mark) in wanIngressMarks)
                {
                    sb.AppendLine($"        iif {iface} ct state new ct mark set 0x{mark:x8}");
                }

                // `return` is mandatory: `meta mark set` is non-terminal, so
                // without it the broad LAN-default rule further down overwrites
                // the mark we just restored.
                sb.AppendLine("        ct direction reply ct mark != 0x00000000 meta mark set ct mark return");
            }

            foreach (var rule in mangleRules.Where(m => m.Enabled && m.Chain == "prerouting").OrderBy(m => m.Priority))
            {
                sb.AppendLine(GenerateMangleRule(rule, markMap));
            }

            sb.AppendLine("    }");
            sb.AppendLine();
            sb.AppendLine("    chain postrouting {");
            sb.AppendLine("        type filter hook postrouting priority mangle; policy accept;");

            foreach (var rule in mangleRules.Where(m => m.Enabled && m.Chain == "postrouting").OrderBy(m => m.Priority))
            {
                sb.AppendLine(GenerateMangleRule(rule, markMap));
            }

            sb.AppendLine("    }");
            sb.AppendLine("}");
        }

        return sb.ToString();
    }

    public async Task<string> GenerateTcScriptAsync(CancellationToken ct = default)
    {
        var sb = new StringBuilder();
        sb.AppendLine("#!/usr/bin/env bash");
        sb.AppendLine("# NetFirewall tc (HTB) configuration");
        sb.AppendLine($"# Generated: {DateTime.UtcNow:O}");
        sb.AppendLine("set -u  # do NOT set -e: tc qdisc del fails when no qdisc is present, that's fine");
        sb.AppendLine();

        var configs = (await GetQosConfigsAsync(ct)).Where(c => c.Enabled && c.InterfaceId.HasValue).ToList();
        if (configs.Count == 0)
        {
            sb.AppendLine("echo 'No QoS configs enabled — nothing to apply.'");
            return sb.ToString();
        }

        var interfaces = await GetInterfacesAsync(ct);
        var ifaceMap = interfaces.ToDictionary(i => i.Id, i => i.Name);
        var marks = await GetTrafficMarksAsync(ct);
        var markMap = marks.ToDictionary(m => m.Id, m => m);

        foreach (var cfg in configs)
        {
            if (!ifaceMap.TryGetValue(cfg.InterfaceId!.Value, out var ifname))
            {
                sb.AppendLine($"# Config {cfg.Id} skipped — interface {cfg.InterfaceId} not found.");
                continue;
            }

            var classes = (await GetQosClassesAsync(cfg.Id, ct)).OrderBy(c => c.Priority).ThenBy(c => c.Name).ToList();

            sb.AppendLine($"# ─── {ifname} — total {cfg.TotalBandwidthMbps} Mbps ───");
            // Reset existing root qdisc on this interface (suppressed if absent).
            sb.AppendLine($"tc qdisc del dev {ifname} root 2>/dev/null || true");

            // HTB root with default class id 1:999 — un-marked traffic falls through to it.
            sb.AppendLine($"tc qdisc add dev {ifname} root handle 1: htb default 999");
            sb.AppendLine($"tc class  add dev {ifname} parent 1: classid 1:1 htb rate {cfg.TotalBandwidthMbps}mbit ceil {cfg.TotalBandwidthMbps}mbit");

            // Each class gets a sequential minor id starting at 10. The default
            // class gets minor 999 with the leftover bandwidth.
            var minor = 10;
            var sumGuaranteed = 0;
            foreach (var c in classes)
            {
                var markName = c.MarkId.HasValue && markMap.TryGetValue(c.MarkId.Value, out var m)
                    ? $"{m.Name} (0x{m.MarkValue:X})"
                    : "(no mark)";
                sb.AppendLine($"# class '{c.Name}' prio {c.Priority} guarantee {c.GuaranteedMbps}mbit ceil {c.CeilingMbps}mbit ← {markName}");
                sb.AppendLine($"tc class  add dev {ifname} parent 1:1 classid 1:{minor} htb rate {c.GuaranteedMbps}mbit ceil {c.CeilingMbps}mbit prio {c.Priority}");
                // Fair queueing inside each class so flows don't starve each other.
                sb.AppendLine($"tc qdisc  add dev {ifname} parent 1:{minor} handle {minor}: fq_codel");

                if (c.MarkId.HasValue && markMap.TryGetValue(c.MarkId.Value, out var mark))
                {
                    sb.AppendLine($"tc filter add dev {ifname} parent 1: protocol ip handle {mark.MarkValue} fw classid 1:{minor}");
                }
                sumGuaranteed += c.GuaranteedMbps;
                minor++;
            }

            // Default class: leftover bandwidth, lowest priority.
            var leftover = Math.Max(1, cfg.TotalBandwidthMbps - sumGuaranteed);
            sb.AppendLine($"# default class — {leftover}mbit leftover for un-marked traffic");
            sb.AppendLine($"tc class  add dev {ifname} parent 1:1 classid 1:999 htb rate {leftover}mbit ceil {cfg.TotalBandwidthMbps}mbit prio 7");
            sb.AppendLine($"tc qdisc  add dev {ifname} parent 1:999 handle 999: fq_codel");
            sb.AppendLine();
        }

        sb.AppendLine("echo 'tc apply complete.'");
        return sb.ToString();
    }

    /// <summary>
    /// In-place: replace each rule's SourceAddresses + DestinationAddresses with
    /// the resolver's flattened CIDR list. Idempotent — pure literals pass through
    /// unchanged. Mutating is safe here because these rule objects are throwaway
    /// (loaded from DB just for this generation pass).
    /// </summary>
    private async Task ResolveAddressesAsync(IReadOnlyList<FwFilterRule> rules, CancellationToken ct)
    {
        foreach (var r in rules)
        {
            if (r.SourceAddresses is { Length: > 0 } src)
                r.SourceAddresses = (await _objectResolver.ResolveAsync(src, ct)).ToArray();
            if (r.DestinationAddresses is { Length: > 0 } dst)
                r.DestinationAddresses = (await _objectResolver.ResolveAsync(dst, ct)).ToArray();
            // L4: expand service names (SSH, HTTP, RTP, …) to numeric ports.
            if (r.DestinationPorts is { Length: > 0 } dp)
                r.DestinationPorts = (await _serviceResolver.ResolveAsync(dp, ct)).ToArray();
        }
    }

    private async Task ResolveAddressesAsync(IReadOnlyList<FwPortForward> rules, CancellationToken ct)
    {
        foreach (var r in rules)
        {
            if (r.SourceAddresses is { Length: > 0 } src)
                r.SourceAddresses = (await _objectResolver.ResolveAsync(src, ct)).ToArray();
        }
    }

    /// <summary>
    /// Mangle rules: resolve named source/destination addresses + named ports
    /// in destination_ports. Same in-place mutation pattern as filter rules.
    /// </summary>
    private async Task ResolveAddressesAsync(IReadOnlyList<FwMangleRule> rules, CancellationToken ct)
    {
        foreach (var r in rules)
        {
            if (r.SourceAddresses is { Length: > 0 } src)
                r.SourceAddresses = (await _objectResolver.ResolveAsync(src, ct)).ToArray();
            if (r.DestinationAddresses is { Length: > 0 } dst)
                r.DestinationAddresses = (await _objectResolver.ResolveAsync(dst, ct)).ToArray();
            if (r.DestinationPorts is { Length: > 0 } dp)
                r.DestinationPorts = (await _serviceResolver.ResolveAsync(dp, ct)).ToArray();
        }
    }

    /// <summary>
    /// NAT rules use a single <c>SourceNetwork</c> string. When that value
    /// resolves to N CIDRs (e.g. it referenced a group with multiple members,
    /// or the operator typed a comma-separated list of literals + names),
    /// we'll emit N nft rules — one per resolved source. Returns a map keyed
    /// by rule id so the caller can fan out the loop.
    /// </summary>
    private async Task<Dictionary<Guid, IReadOnlyList<string>>> ResolveNatSourcesAsync(
        IReadOnlyList<FwNatRule> rules, CancellationToken ct)
    {
        var dict = new Dictionary<Guid, IReadOnlyList<string>>(rules.Count);
        foreach (var r in rules)
        {
            if (string.IsNullOrWhiteSpace(r.SourceNetwork))
            {
                dict[r.Id] = Array.Empty<string>();
                continue;
            }
            // Allow comma-separated values in the field too — same UX as
            // filter/PF where multi-source typing is natural.
            var inputs = r.SourceNetwork
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            dict[r.Id] = await _objectResolver.ResolveAsync(inputs, ct);
        }
        return dict;
    }

    private static string GenerateFilterRule(FwFilterRule rule, Dictionary<Guid, string> ifaceMap)
    {
        var sb = new StringBuilder("        ");

        // Interface conditions
        if (rule.InterfaceInId.HasValue && ifaceMap.TryGetValue(rule.InterfaceInId.Value, out var ifIn))
        {
            sb.Append($"iif {ifIn} ");
        }
        if (rule.InterfaceOutId.HasValue && ifaceMap.TryGetValue(rule.InterfaceOutId.Value, out var ifOut))
        {
            sb.Append($"oif {ifOut} ");
        }

        // Protocol
        if (!string.IsNullOrEmpty(rule.Protocol))
        {
            sb.Append($"ip protocol {rule.Protocol} ");
        }

        // Connection tracking
        if (rule.ConnectionState is { Length: > 0 })
        {
            sb.Append($"ct state {{ {string.Join(", ", rule.ConnectionState)} }} ");
        }

        // Source addresses
        if (rule.SourceAddresses is { Length: > 0 })
        {
            if (rule.SourceAddresses.Length == 1)
                sb.Append($"ip saddr {rule.SourceAddresses[0]} ");
            else
                sb.Append($"ip saddr {{ {string.Join(", ", rule.SourceAddresses)} }} ");
        }

        // Destination addresses
        if (rule.DestinationAddresses is { Length: > 0 })
        {
            if (rule.DestinationAddresses.Length == 1)
                sb.Append($"ip daddr {rule.DestinationAddresses[0]} ");
            else
                sb.Append($"ip daddr {{ {string.Join(", ", rule.DestinationAddresses)} }} ");
        }

        // Destination ports
        if (rule.DestinationPorts is { Length: > 0 } && !string.IsNullOrEmpty(rule.Protocol))
        {
            if (rule.DestinationPorts.Length == 1)
                sb.Append($"{rule.Protocol} dport {rule.DestinationPorts[0]} ");
            else
                sb.Append($"{rule.Protocol} dport {{ {string.Join(", ", rule.DestinationPorts)} }} ");
        }

        // Rate limit
        if (!string.IsNullOrEmpty(rule.RateLimit))
        {
            sb.Append($"limit rate {rule.RateLimit} ");
        }

        // Log prefix
        if (!string.IsNullOrEmpty(rule.LogPrefix))
        {
            sb.Append($"log prefix \"{rule.LogPrefix}\" ");
        }

        // Action
        sb.Append(rule.Action);

        // Comment
        if (!string.IsNullOrEmpty(rule.Description))
        {
            sb.Append($" comment \"{EscapeComment(rule.Description)}\"");
        }

        return sb.ToString();
    }

    /// <summary>
    /// nft first-match-wins, so comment text is not part of what the packet
    /// hits. Two TIME-LIMIT drops for the same saddr with different
    /// descriptions are the same rule.
    /// </summary>
    internal static string FilterLineDedupeKey(string line)
    {
        var s = line.Trim();
        var idx = s.LastIndexOf(" comment ", StringComparison.Ordinal);
        return idx >= 0 ? s[..idx].TrimEnd() : s;
    }

    /// <summary>
    /// Emit one DNAT rule, or <c>null</c> when the row is too incomplete to make
    /// a valid nft statement. A malformed rule (empty protocol, no port, no
    /// target) would produce a line without a verdict — and `nft -f` rejects the
    /// WHOLE ruleset on a single syntax error, so one bad DB row would take the
    /// entire firewall apply down. Returning null lets the caller emit a `# SKIP`
    /// comment instead, keeping the rest of the ruleset valid.
    /// </summary>
    private static string? GeneratePortForwardRule(FwPortForward pf, Dictionary<Guid, string> ifaceMap)
    {
        // Guard: a DNAT needs a protocol, an external port, and a target.
        if (string.IsNullOrWhiteSpace(pf.Protocol)) return null;
        if (pf.ExternalPortStart <= 0) return null;
        if (pf.InternalIp is null || pf.InternalIp.Equals(IPAddress.None) || pf.InternalPort <= 0) return null;

        var sb = new StringBuilder("        ");

        // Interface
        if (pf.InterfaceId.HasValue && ifaceMap.TryGetValue(pf.InterfaceId.Value, out var iface))
        {
            sb.Append($"iif {iface} ");
        }

        // Source address restrictions go BEFORE the L4 protocol token. nft
        // refuses `udp ip saddr {...} dport ...` — it expects `ip saddr {...}
        // udp dport ...`. Same for tcp.
        if (pf.SourceAddresses is { Length: > 0 })
        {
            if (pf.SourceAddresses.Length == 1)
                sb.Append($"ip saddr {pf.SourceAddresses[0]} ");
            else
                sb.Append($"ip saddr {{ {string.Join(", ", pf.SourceAddresses)} }} ");
        }

        // Protocol (handle tcp/udp) — now adjacent to dport, which is what nft expects.
        //
        // nft has no bare `dport`: it must be qualified by the L4 protocol
        // (`tcp dport 53`) or, when the rule spans several protocols, by `th`
        // — the transport header, which exposes sport/dport for any L4 proto.
        // `meta l4proto { tcp, udp } dport 53` is a SYNTAX ERROR, and `nft -f`
        // rejects the WHOLE ruleset on one bad line, so a single "TCP + UDP"
        // port forward (the natural choice for DNS) would take the entire
        // apply down — not just its own rule.
        var protocols = pf.Protocol.ToLower()
            .Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        string portMatcher;
        if (protocols.Length == 1)
        {
            portMatcher = protocols[0];
        }
        else
        {
            sb.Append($"meta l4proto {{ {string.Join(", ", protocols)} }} ");
            portMatcher = "th";
        }

        // Port range
        if (pf.ExternalPortEnd.HasValue && pf.ExternalPortEnd != pf.ExternalPortStart)
        {
            sb.Append($"{portMatcher} dport {pf.ExternalPortStart}-{pf.ExternalPortEnd} ");
        }
        else
        {
            sb.Append($"{portMatcher} dport {pf.ExternalPortStart} ");
        }

        // DNAT
        sb.Append($"dnat to {pf.InternalIp}:{pf.InternalPort}");

        // Comment
        if (!string.IsNullOrEmpty(pf.Description))
        {
            sb.Append($" comment \"{EscapeComment(pf.Description)}\"");
        }

        return sb.ToString();
    }

    /// <summary>
    /// Emit one NAT rule. <paramref name="sourceCidr"/> is the resolved value
    /// from <see cref="ResolveNatSourcesAsync"/> — this generator is called
    /// once per resolved source, so a group of N members produces N rules.
    /// </summary>
    private static string? GenerateNatRule(FwNatRule nat, string sourceCidr, Dictionary<Guid, string> ifaceMap)
    {
        // Determine the verdict first — if we can't form a valid one, skip the
        // rule entirely rather than emit `ip saddr X oif Y` with no action.
        // nft rejects the whole ruleset on one bad line, so a misconfigured row
        // (e.g. snat type with a null snat_address) must NOT reach the script.
        string action;
        if (nat.Type.Equals("masquerade", StringComparison.OrdinalIgnoreCase))
        {
            action = "masquerade";
        }
        else if (nat.Type.Equals("snat", StringComparison.OrdinalIgnoreCase)
                 && nat.SnatAddress is not null && !nat.SnatAddress.Equals(IPAddress.None))
        {
            action = $"snat to {nat.SnatAddress}";
        }
        else
        {
            return null; // unknown type, or snat without an address — not renderable
        }

        var sb = new StringBuilder("        ");

        // Source network (resolved — could be a literal CIDR or one of N from a group)
        sb.Append($"ip saddr {sourceCidr} ");

        // Output interface
        if (nat.OutputInterfaceId.HasValue && ifaceMap.TryGetValue(nat.OutputInterfaceId.Value, out var iface))
        {
            sb.Append($"oif {iface} ");
        }

        sb.Append(action);

        // Comment
        if (!string.IsNullOrEmpty(nat.Description))
        {
            sb.Append($" comment \"{EscapeComment(nat.Description)}\"");
        }

        return sb.ToString();
    }

    private static string GenerateMangleRule(FwMangleRule rule, Dictionary<Guid, FwTrafficMark> markMap)
    {
        var sb = new StringBuilder("        ");

        // Protocol
        if (!string.IsNullOrEmpty(rule.Protocol))
        {
            sb.Append($"ip protocol {rule.Protocol} ");
        }

        // Source addresses
        if (rule.SourceAddresses is { Length: > 0 })
        {
            if (rule.SourceAddresses.Length == 1)
                sb.Append($"ip saddr {rule.SourceAddresses[0]} ");
            else
                sb.Append($"ip saddr {{ {string.Join(", ", rule.SourceAddresses)} }} ");
        }

        // Destination addresses
        if (rule.DestinationAddresses is { Length: > 0 })
        {
            if (rule.DestinationAddresses.Length == 1)
                sb.Append($"ip daddr {rule.DestinationAddresses[0]} ");
            else
                sb.Append($"ip daddr {{ {string.Join(", ", rule.DestinationAddresses)} }} ");
        }

        // Destination ports
        if (rule.DestinationPorts is { Length: > 0 } && !string.IsNullOrEmpty(rule.Protocol))
        {
            if (rule.DestinationPorts.Length == 1)
                sb.Append($"{rule.Protocol} dport {rule.DestinationPorts[0]} ");
            else
                sb.Append($"{rule.Protocol} dport {{ {string.Join(", ", rule.DestinationPorts)} }} ");
        }

        // Mark action. `meta mark set` is an action, not a verdict — packet
        // evaluation continues, so any later rule whose match also fits would
        // overwrite the mark (e.g. a broad "LAN → WAN1" 0.0.0.0/0 rule clobbers
        // a specific "host → VPN" mark set just above it). Emit `return` right
        // after marking so the first matching rule (lowest priority value) wins
        // and the packet leaves the chain with its intended mark intact.
        if (rule.MarkId.HasValue && markMap.TryGetValue(rule.MarkId.Value, out var mark))
        {
            sb.Append($"meta mark set 0x{mark.MarkValue:x} return");
        }

        // Comment
        if (!string.IsNullOrEmpty(rule.Description))
        {
            sb.Append($" comment \"{EscapeComment(rule.Description)}\"");
        }

        return sb.ToString();
    }

    private static string EscapeComment(string comment)
    {
        return comment.Replace("\"", "'").Replace("\n", " ").Replace("\r", "");
    }

    /// <summary>
    /// WAN interfaces paired with the fwmark that routes traffic out of them.
    /// Used to make an inbound (DNAT'd) connection answer through the interface
    /// it arrived on — see the ingress-marking block in
    /// <see cref="GenerateNftablesConfigAsync"/>.
    ///
    /// <para>The mapping is read from <c>wan_health_config.probe_fwmark</c>,
    /// which already means exactly this: the fwmark that makes a packet leave
    /// through this WAN. The failover monitor stamps it on its probes so they
    /// egress the link being measured. Reusing it keeps ONE operator-visible
    /// place for the fact (Monitoring → WAN failover) instead of a second
    /// column that could silently drift out of sync with the first — and it
    /// gives the value two consumers, so a wrong entry shows up as broken
    /// failover probes as well as unreachable inbound services.</para>
    ///
    /// <para>Deliberately NOT derived from <c>fw_static_routes.table_id</c>:
    /// that column is read by the policy-routing applier but written by
    /// nothing — no service method and no UI sets it — so on a host whose
    /// routing tables were set up by hand it is always NULL.</para>
    ///
    /// <para>Fail-soft, like the schedule loader below: on a host whose
    /// migrations are behind (the column arrived in 00026) this returns empty
    /// and the generator emits no ingress marking.</para>
    /// </summary>
    private async Task<IReadOnlyList<(string Interface, long Fwmark)>> GetWanIngressMarksAsync(CancellationToken ct)
    {
        const string sql = @"
            SELECT i.name AS name, w.probe_fwmark AS fwmark
              FROM fw_interfaces     i
              JOIN wan_health_config w ON w.interface_id = i.id AND w.enabled
             WHERE i.type = 'WAN' AND i.enabled AND w.probe_fwmark IS NOT NULL
             ORDER BY i.name";

        try
        {
            await using var conn = await _dataSource.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            await using var reader = await cmd.ExecuteReaderAsync(ct);

            var list = new List<(string, long)>();
            while (await reader.ReadAsync(ct))
                list.Add((reader.GetString(0), reader.GetInt64(1)));
            return list;
        }
        catch (PostgresException ex) when (ex.SqlState is "42P01" or "42703")
        {
            _logger.LogDebug(
                "wan_health_config.probe_fwmark not present — dual-WAN ingress marking skipped. " +
                "Inbound services on a secondary WAN will answer through the primary one.");
            return Array.Empty<(string, long)>();
        }
    }

    /// <summary>
    /// Load all enabled schedules for use during nft generation. Tolerant of
    /// the table being absent (migration 19 not applied yet) — returns empty
    /// so all rules effectively "always-on" until the operator runs the migration.
    /// </summary>
    private async Task<IReadOnlyList<FwSchedule>> GetSchedulesForGenerationAsync(CancellationToken ct)
    {
        try
        {
            await using var conn = await _dataSource.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(
                "SELECT * FROM fw_schedules WHERE enabled = true", conn);
            var list = new List<FwSchedule>();
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                list.Add(new FwSchedule
                {
                    Id          = reader.GetGuid(reader.GetOrdinal("id")),
                    Name        = reader.GetString(reader.GetOrdinal("name")),
                    DaysOfWeek  = (int[])reader["days_of_week"],
                    // Npgsql 10 maps `time` to TimeOnly; convert to TimeSpan to match the model.
                    StartTime   = ((TimeOnly)reader["start_time"]).ToTimeSpan(),
                    EndTime     = ((TimeOnly)reader["end_time"]).ToTimeSpan(),
                    Timezone    = reader.GetString(reader.GetOrdinal("timezone")),
                    Enabled     = reader.GetBoolean(reader.GetOrdinal("enabled"))
                });
            }
            return list;
        }
        catch (PostgresException ex) when (ex.SqlState == "42P01")
        {
            _logger.LogDebug("fw_schedules missing — schedule gating disabled, all rules treated as always-on.");
            return Array.Empty<FwSchedule>();
        }
    }

    /// <summary>
    /// Read a nullable uuid column without exploding when the column doesn't
    /// exist yet (e.g. <c>schedule_id</c> on a DB where migration 19 hasn't run).
    /// </summary>
    private static bool SafeBool(NpgsqlDataReader r, string col, bool fallback = false)
    {
        try
        {
            var ord = r.GetOrdinal(col);
            return r.IsDBNull(ord) ? fallback : r.GetBoolean(ord);
        }
        catch (IndexOutOfRangeException)
        {
            return fallback;
        }
    }

    private static Guid? SafeNullableGuid(NpgsqlDataReader r, string col)
    {
        try
        {
            var ord = r.GetOrdinal(col);
            return r.IsDBNull(ord) ? null : r.GetGuid(ord);
        }
        catch (IndexOutOfRangeException)
        {
            return null;
        }
    }

    #endregion
}
