using Microsoft.Extensions.Logging;
using Npgsql;

namespace NetFirewall.Services.Firewall;

public sealed class ApplyHistoryService : IApplyHistoryService
{
    private readonly NpgsqlDataSource _ds;
    private readonly ILogger<ApplyHistoryService> _logger;

    // Maps each Apply kind to the audit-log table_name patterns it depends on.
    // When any of these rows has a created_at later than the last successful
    // apply, we consider the kind "dirty".
    private static readonly Dictionary<string, string[]> KindToTables = new(StringComparer.OrdinalIgnoreCase)
    {
        // nftables Apply covers all the firewall rule tables + interfaces + traffic marks.
        ["nftables"] = new[]
        {
            "fw_interfaces", "fw_filter_rules", "fw_port_forwards",
            "fw_nat_rules", "fw_mangle_rules", "fw_traffic_marks", "fw_static_routes"
        },
        // tc Apply depends on QoS config + classes (which reference traffic marks).
        ["tc"]        = new[] { "fw_qos_config", "fw_qos_classes" },
        // WireGuard apply tracks its own tables.
        ["wireguard"] = new[] { "wg_servers", "wg_peers" }
    };

    public ApplyHistoryService(NpgsqlDataSource ds, ILogger<ApplyHistoryService> logger)
    {
        _ds = ds;
        _logger = logger;
    }

    public async Task RecordAsync(string kind, bool success, int? exitCode, string? message, string? appliedBy, CancellationToken ct = default)
    {
        try
        {
            await using var conn = await _ds.OpenConnectionAsync(ct);
            const string sql = @"
                INSERT INTO fw_apply_history (id, kind, success, applied_at, applied_by, exit_code, message)
                VALUES (@id, @kind, @success, now(), @by, @exit, @msg)";
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("id", Guid.NewGuid());
            cmd.Parameters.AddWithValue("kind", kind);
            cmd.Parameters.AddWithValue("success", success);
            cmd.Parameters.AddWithValue("by",   (object?)appliedBy ?? DBNull.Value);
            cmd.Parameters.AddWithValue("exit", (object?)exitCode  ?? DBNull.Value);
            cmd.Parameters.AddWithValue("msg",  (object?)message   ?? DBNull.Value);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        catch (Exception ex)
        {
            // Recording is best-effort — never fail the actual Apply because of audit/history failure.
            _logger.LogWarning(ex, "Failed to record apply-history entry for {Kind}", kind);
        }
    }

    public async Task<DateTime?> LastSuccessAsync(string kind, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "SELECT MAX(applied_at) FROM fw_apply_history WHERE kind = @kind AND success = true",
            conn);
        cmd.Parameters.AddWithValue("kind", kind);
        var result = await cmd.ExecuteScalarAsync(ct);
        return result is DateTime dt ? dt : null;
    }

    public async Task<IReadOnlyList<PendingChangesSummary>> GetPendingSummaryAsync(CancellationToken ct = default)
    {
        var list = new List<PendingChangesSummary>();
        await using var conn = await _ds.OpenConnectionAsync(ct);

        foreach (var (kind, tables) in KindToTables)
        {
            var lastApplied = await GetLastSuccessInternalAsync(conn, kind, ct);

            // Count rows changed since lastApplied (or all rows if never applied).
            // We look at fw_audit_log because not every fw_* table has updated_at —
            // and even when it does, deletes wouldn't be visible. Audit log captures everything.
            var sql = lastApplied is null
                ? "SELECT COUNT(DISTINCT record_id) FROM fw_audit_log WHERE table_name = ANY(@tables)"
                : "SELECT COUNT(DISTINCT record_id) FROM fw_audit_log WHERE table_name = ANY(@tables) AND created_at > @since";

            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("tables", tables);
            if (lastApplied is not null)
                cmd.Parameters.AddWithValue("since", lastApplied.Value);

            var pending = Convert.ToInt32(await cmd.ExecuteScalarAsync(ct) ?? 0);
            list.Add(new PendingChangesSummary(kind, lastApplied, pending));
        }

        return list;
    }

    public async Task<IReadOnlyList<ApplyHistoryEntry>> RecentAsync(int limit = 10, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(@"
            SELECT id, kind, success, applied_at, applied_by, exit_code, message
            FROM fw_apply_history
            ORDER BY applied_at DESC
            LIMIT @limit", conn);
        cmd.Parameters.AddWithValue("limit", limit);
        var list = new List<ApplyHistoryEntry>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            list.Add(new ApplyHistoryEntry(
                r.GetGuid(0),
                r.GetString(1),
                r.GetBoolean(2),
                r.GetDateTime(3),
                r.IsDBNull(4) ? null : r.GetString(4),
                r.IsDBNull(5) ? null : r.GetInt32(5),
                r.IsDBNull(6) ? null : r.GetString(6)));
        }
        return list;
    }

    private static async Task<DateTime?> GetLastSuccessInternalAsync(NpgsqlConnection conn, string kind, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand(
            "SELECT MAX(applied_at) FROM fw_apply_history WHERE kind = @kind AND success = true",
            conn);
        cmd.Parameters.AddWithValue("kind", kind);
        var result = await cmd.ExecuteScalarAsync(ct);
        return result is DateTime dt ? dt : null;
    }
}
