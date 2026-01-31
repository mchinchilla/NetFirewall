using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Firewall;
using Npgsql;

namespace NetFirewall.Services.Firewall;

/// <summary>
/// Firewall service for managing nftables configuration stored in PostgreSQL.
/// Provides CRUD operations and nftables.conf generation.
/// </summary>
public sealed class FirewallService : IFirewallService
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly ILogger<FirewallService> _logger;

    public FirewallService(NpgsqlDataSource dataSource, ILogger<FirewallService> logger)
    {
        _dataSource = dataSource;
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

    public async Task<FwInterface> CreateInterfaceAsync(FwInterface iface, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        iface.Id = Guid.NewGuid();
        iface.CreatedAt = DateTime.UtcNow;
        iface.UpdatedAt = DateTime.UtcNow;

        const string sql = @"
            INSERT INTO fw_interfaces (id, name, type, role, ip_address, subnet_mask, gateway, enabled, created_at, updated_at)
            VALUES (@id, @name, @type, @role, @ip, @subnet, @gateway, @enabled, @created, @updated)";

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
                subnet_mask = @subnet, gateway = @gateway, enabled = @enabled, updated_at = @updated
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
            list.Add(new FwInterface
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
        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        rule.Id = Guid.NewGuid();
        rule.CreatedAt = DateTime.UtcNow;

        const string sql = @"
            INSERT INTO fw_filter_rules (id, chain, description, action, protocol, interface_in_id, interface_out_id,
                source_addresses, destination_addresses, destination_ports, connection_state, rate_limit, log_prefix,
                enabled, priority, created_at)
            VALUES (@id, @chain, @desc, @action, @proto, @ifin, @ifout, @src, @dst, @ports, @state, @rate, @log, @enabled, @priority, @created)";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddFilterRuleParams(cmd, rule);

        await cmd.ExecuteNonQueryAsync(ct);

        await LogAuditAsync("fw_filter_rules", rule.Id, "INSERT", null, rule, null, ct);

        _logger.LogInformation("Created filter rule: {Desc}", rule.Description ?? rule.Action);
        return rule;
    }

    public async Task<FwFilterRule> UpdateFilterRuleAsync(FwFilterRule rule, CancellationToken ct = default)
    {
        var existing = await GetFilterRuleByIdAsync(rule.Id, ct);

        await using var conn = await _dataSource.OpenConnectionAsync(ct);

        const string sql = @"
            UPDATE fw_filter_rules
            SET chain = @chain, description = @desc, action = @action, protocol = @proto,
                interface_in_id = @ifin, interface_out_id = @ifout, source_addresses = @src,
                destination_addresses = @dst, destination_ports = @ports, connection_state = @state,
                rate_limit = @rate, log_prefix = @log, enabled = @enabled, priority = @priority
            WHERE id = @id";

        await using var cmd = new NpgsqlCommand(sql, conn);
        AddFilterRuleParams(cmd, rule);

        await cmd.ExecuteNonQueryAsync(ct);

        await LogAuditAsync("fw_filter_rules", rule.Id, "UPDATE", existing, rule, null, ct);

        return rule;
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
        const string sql = "SELECT * FROM fw_nat_rules ORDER BY priority, type";

        await using var cmd = new NpgsqlCommand(sql, conn);
        return await ReadNatRulesAsync(cmd, ct);
    }

    public async Task<FwNatRule?> GetNatRuleByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = "SELECT * FROM fw_nat_rules WHERE id = @id";

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

        const string sql = @"
            INSERT INTO fw_nat_rules (id, type, description, source_network, output_interface_id, snat_address, enabled, priority, created_at)
            VALUES (@id, @type, @desc, @src, @iface, @snat, @enabled, @priority, @created)";

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
            SET type = @type, description = @desc, source_network = @src, output_interface_id = @iface,
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
            cmd.Parameters.AddWithValue("old", oldValues != null ? JsonSerializer.Serialize(oldValues) : DBNull.Value);
            cmd.Parameters.AddWithValue("new", newValues != null ? JsonSerializer.Serialize(newValues) : DBNull.Value);
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

        // Create interface name lookup
        var ifaceMap = interfaces.ToDictionary(i => i.Id, i => i.Name);
        var markMap = trafficMarks.ToDictionary(m => m.Id, m => m);

        // NAT table (for port forwards and masquerade/snat)
        sb.AppendLine("table ip nat {");
        sb.AppendLine("    chain prerouting {");
        sb.AppendLine("        type nat hook prerouting priority dstnat; policy accept;");

        // Port forwards (DNAT)
        foreach (var pf in portForwards.Where(p => p.Enabled))
        {
            sb.AppendLine(GeneratePortForwardRule(pf, ifaceMap));
        }

        sb.AppendLine("    }");
        sb.AppendLine();
        sb.AppendLine("    chain postrouting {");
        sb.AppendLine("        type nat hook postrouting priority srcnat; policy accept;");

        // NAT rules (masquerade/snat)
        foreach (var nat in natRules.Where(n => n.Enabled))
        {
            sb.AppendLine(GenerateNatRule(nat, ifaceMap));
        }

        sb.AppendLine("    }");
        sb.AppendLine("}");
        sb.AppendLine();

        // Filter table
        sb.AppendLine("table ip filter {");

        // Input chain
        sb.AppendLine("    chain input {");
        sb.AppendLine("        type filter hook input priority filter; policy drop;");
        sb.AppendLine("        iif lo accept");

        foreach (var rule in filterRules.Where(r => r.Enabled && r.Chain == "input").OrderBy(r => r.Priority))
        {
            sb.AppendLine(GenerateFilterRule(rule, ifaceMap));
        }

        sb.AppendLine("    }");
        sb.AppendLine();

        // Forward chain
        sb.AppendLine("    chain forward {");
        sb.AppendLine("        type filter hook forward priority filter; policy drop;");

        foreach (var rule in filterRules.Where(r => r.Enabled && r.Chain == "forward").OrderBy(r => r.Priority))
        {
            sb.AppendLine(GenerateFilterRule(rule, ifaceMap));
        }

        sb.AppendLine("    }");
        sb.AppendLine();

        // Output chain
        sb.AppendLine("    chain output {");
        sb.AppendLine("        type filter hook output priority filter; policy accept;");

        foreach (var rule in filterRules.Where(r => r.Enabled && r.Chain == "output").OrderBy(r => r.Priority))
        {
            sb.AppendLine(GenerateFilterRule(rule, ifaceMap));
        }

        sb.AppendLine("    }");
        sb.AppendLine("}");
        sb.AppendLine();

        // Mangle table (for QoS marking)
        if (mangleRules.Any(m => m.Enabled))
        {
            sb.AppendLine("table ip mangle {");
            sb.AppendLine("    chain prerouting {");
            sb.AppendLine("        type filter hook prerouting priority mangle; policy accept;");

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

    private static string GeneratePortForwardRule(FwPortForward pf, Dictionary<Guid, string> ifaceMap)
    {
        var sb = new StringBuilder("        ");

        // Interface
        if (pf.InterfaceId.HasValue && ifaceMap.TryGetValue(pf.InterfaceId.Value, out var iface))
        {
            sb.Append($"iif {iface} ");
        }

        // Protocol (handle tcp/udp)
        var protocols = pf.Protocol.ToLower().Split('/');
        if (protocols.Length == 1)
        {
            sb.Append($"{protocols[0]} ");
        }
        else
        {
            // For tcp/udp, we generate separate rules in practice, but here we simplify
            sb.Append($"meta l4proto {{ tcp, udp }} ");
        }

        // Source address restrictions
        if (pf.SourceAddresses is { Length: > 0 })
        {
            if (pf.SourceAddresses.Length == 1)
                sb.Append($"ip saddr {pf.SourceAddresses[0]} ");
            else
                sb.Append($"ip saddr {{ {string.Join(", ", pf.SourceAddresses)} }} ");
        }

        // Port range
        if (pf.ExternalPortEnd.HasValue && pf.ExternalPortEnd != pf.ExternalPortStart)
        {
            sb.Append($"dport {pf.ExternalPortStart}-{pf.ExternalPortEnd} ");
        }
        else
        {
            sb.Append($"dport {pf.ExternalPortStart} ");
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

    private static string GenerateNatRule(FwNatRule nat, Dictionary<Guid, string> ifaceMap)
    {
        var sb = new StringBuilder("        ");

        // Source network
        sb.Append($"ip saddr {nat.SourceNetwork} ");

        // Output interface
        if (nat.OutputInterfaceId.HasValue && ifaceMap.TryGetValue(nat.OutputInterfaceId.Value, out var iface))
        {
            sb.Append($"oif {iface} ");
        }

        // NAT action
        if (nat.Type.Equals("masquerade", StringComparison.OrdinalIgnoreCase))
        {
            sb.Append("masquerade");
        }
        else if (nat.Type.Equals("snat", StringComparison.OrdinalIgnoreCase) && nat.SnatAddress != null)
        {
            sb.Append($"snat to {nat.SnatAddress}");
        }

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

        // Mark action
        if (rule.MarkId.HasValue && markMap.TryGetValue(rule.MarkId.Value, out var mark))
        {
            sb.Append($"meta mark set 0x{mark.MarkValue:x}");
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

    #endregion
}
