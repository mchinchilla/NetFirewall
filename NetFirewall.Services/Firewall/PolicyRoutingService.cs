using Microsoft.Extensions.Logging;
using NetFirewall.Models.Firewall;
using Npgsql;

namespace NetFirewall.Services.Firewall;

public sealed class PolicyRoutingService : IPolicyRoutingService
{
    private readonly NpgsqlDataSource _ds;
    private readonly ILogger<PolicyRoutingService> _logger;

    public PolicyRoutingService(NpgsqlDataSource ds, ILogger<PolicyRoutingService> logger)
    {
        _ds = ds;
        _logger = logger;
    }

    public async Task<IReadOnlyList<FwRouteTable>> GetRouteTablesAsync(CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "SELECT id, table_id, table_name, description, enabled, created_at FROM fw_route_tables ORDER BY table_id", conn);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        var list = new List<FwRouteTable>();
        while (await r.ReadAsync(ct))
        {
            list.Add(new FwRouteTable
            {
                Id = r.GetGuid(0),
                TableId = r.GetInt32(1),
                Name = r.GetString(2),
                Description = r.IsDBNull(3) ? null : r.GetString(3),
                Enabled = r.GetBoolean(4),
                CreatedAt = r.GetDateTime(5),
            });
        }
        return list;
    }

    public async Task<IReadOnlyList<FwPolicyRule>> GetPolicyRulesAsync(CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "SELECT id, fwmark, table_name, priority, description, enabled, created_at FROM fw_policy_rules ORDER BY priority NULLS LAST, fwmark", conn);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        var list = new List<FwPolicyRule>();
        while (await r.ReadAsync(ct))
        {
            list.Add(new FwPolicyRule
            {
                Id = r.GetGuid(0),
                Fwmark = r.GetInt64(1),
                TableName = r.GetString(2),
                Priority = r.IsDBNull(3) ? null : r.GetInt32(3),
                Description = r.IsDBNull(4) ? null : r.GetString(4),
                Enabled = r.GetBoolean(5),
                CreatedAt = r.GetDateTime(6),
            });
        }
        return list;
    }

    // ── write-side ──

    public async Task<FwRouteTable?> GetRouteTableByNameAsync(string name, CancellationToken ct = default)
        => (await GetRouteTablesAsync(ct)).FirstOrDefault(t =>
               string.Equals(t.Name, name, StringComparison.OrdinalIgnoreCase));

    public async Task<FwPolicyRule?> GetPolicyRuleByTableNameAsync(string tableName, CancellationToken ct = default)
        => (await GetPolicyRulesAsync(ct)).FirstOrDefault(p =>
               string.Equals(p.TableName, tableName, StringComparison.OrdinalIgnoreCase));

    public async Task<FwRouteTable> EnsureRouteTableAsync(int tableId, string name, string? description, CancellationToken ct = default)
    {
        // Discover first — by NAME (the operator-facing identity) then by table_id.
        var existing = await GetRouteTableByNameAsync(name, ct);
        if (existing is not null) return existing;
        var all = await GetRouteTablesAsync(ct);
        var byId = all.FirstOrDefault(t => t.TableId == tableId);
        if (byId is not null) return byId; // id taken by another name — caller should re-allocate; return what's there

        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO fw_route_tables (table_id, table_name, description, enabled)
            VALUES (@tid, @name, @desc, true)
            ON CONFLICT (table_name) DO NOTHING
            RETURNING id, table_id, table_name, description, enabled, created_at", conn);
        cmd.Parameters.AddWithValue("tid", tableId);
        cmd.Parameters.AddWithValue("name", name);
        cmd.Parameters.AddWithValue("desc", (object?)description ?? DBNull.Value);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        if (await r.ReadAsync(ct))
            return new FwRouteTable
            {
                Id = r.GetGuid(0), TableId = r.GetInt32(1), Name = r.GetString(2),
                Description = r.IsDBNull(3) ? null : r.GetString(3),
                Enabled = r.GetBoolean(4), CreatedAt = r.GetDateTime(5),
            };
        // Conflict raced us — re-read.
        return (await GetRouteTableByNameAsync(name, ct))!;
    }

    public async Task<FwPolicyRule> EnsurePolicyRuleAsync(long fwmark, string tableName, int? priority, string? description, CancellationToken ct = default)
    {
        var existing = (await GetPolicyRulesAsync(ct)).FirstOrDefault(p =>
            p.Fwmark == fwmark &&
            string.Equals(p.TableName, tableName, StringComparison.OrdinalIgnoreCase));
        if (existing is not null) return existing;

        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO fw_policy_rules (fwmark, table_name, priority, description, enabled)
            VALUES (@fw, @tn, @prio, @desc, true)
            RETURNING id, fwmark, table_name, priority, description, enabled, created_at", conn);
        cmd.Parameters.AddWithValue("fw", fwmark);
        cmd.Parameters.AddWithValue("tn", tableName);
        cmd.Parameters.AddWithValue("prio", (object?)priority ?? DBNull.Value);
        cmd.Parameters.AddWithValue("desc", (object?)description ?? DBNull.Value);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        await r.ReadAsync(ct);
        return new FwPolicyRule
        {
            Id = r.GetGuid(0), Fwmark = r.GetInt64(1), TableName = r.GetString(2),
            Priority = r.IsDBNull(3) ? null : r.GetInt32(3),
            Description = r.IsDBNull(4) ? null : r.GetString(4),
            Enabled = r.GetBoolean(5), CreatedAt = r.GetDateTime(6),
        };
    }

    public async Task<int> AllocateTableIdAsync(CancellationToken ct = default)
    {
        var used = (await GetRouteTablesAsync(ct)).Select(t => t.TableId).ToHashSet();
        for (var id = 200; id <= 252; id++)
            if (!used.Contains(id)) return id;
        throw new InvalidOperationException("No free route-table id in [200,252].");
    }
}
