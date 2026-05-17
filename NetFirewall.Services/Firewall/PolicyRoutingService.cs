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
}
