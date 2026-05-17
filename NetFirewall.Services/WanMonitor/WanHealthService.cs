using NetFirewall.Models.WanMonitor;
using Npgsql;

namespace NetFirewall.Services.WanMonitor;

public sealed class WanHealthService : IWanHealthService
{
    private readonly NpgsqlDataSource _ds;

    public WanHealthService(NpgsqlDataSource ds) => _ds = ds;

    public async Task<IReadOnlyList<WanHealthConfig>> GetConfigsAsync(CancellationToken ct = default)
    {
        const string sql = @"
            SELECT c.id, c.interface_id, c.priority, c.monitor_targets,
                   c.failover_threshold, c.recovery_threshold, c.enabled,
                   c.created_at, c.updated_at, i.name, c.probe_fwmark
            FROM wan_health_config c
            JOIN fw_interfaces i ON i.id = c.interface_id
            WHERE c.enabled = true AND i.enabled = true
            ORDER BY c.priority, i.name";
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        var list = new List<WanHealthConfig>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            list.Add(new WanHealthConfig
            {
                Id                 = r.GetGuid(0),
                InterfaceId        = r.GetGuid(1),
                Priority           = r.GetInt32(2),
                MonitorTargets     = r.IsDBNull(3) ? Array.Empty<string>() : (string[])r["monitor_targets"],
                FailoverThreshold  = r.GetInt32(4),
                RecoveryThreshold  = r.GetInt32(5),
                Enabled            = r.GetBoolean(6),
                CreatedAt          = r.GetDateTime(7),
                UpdatedAt          = r.GetDateTime(8),
                InterfaceName      = r.GetString(9),
                ProbeFwmark        = r.IsDBNull(10) ? null : r.GetInt64(10),
            });
        }
        return list;
    }

    public async Task<IReadOnlyList<WanHealthState>> GetStateAsync(CancellationToken ct = default)
    {
        const string sql = @"
            SELECT s.interface_id, s.is_up, s.consecutive_failures, s.consecutive_successes,
                   s.last_check_at, s.last_transition_at, s.last_rtt_ms, s.last_target, s.last_error,
                   i.name, COALESCE(i.role, '')
            FROM wan_health_state s
            JOIN fw_interfaces i ON i.id = s.interface_id
            ORDER BY i.name";
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        var list = new List<WanHealthState>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            list.Add(new WanHealthState
            {
                InterfaceId           = r.GetGuid(0),
                IsUp                  = r.GetBoolean(1),
                ConsecutiveFailures   = r.GetInt32(2),
                ConsecutiveSuccesses  = r.GetInt32(3),
                LastCheckAt           = r.GetDateTime(4),
                LastTransitionAt      = r.GetDateTime(5),
                LastRttMs             = r.IsDBNull(6) ? null : r.GetDouble(6),
                LastTarget            = r.IsDBNull(7) ? null : r.GetString(7),
                LastError             = r.IsDBNull(8) ? null : r.GetString(8),
                InterfaceName         = r.GetString(9),
                Role                  = r.GetString(10),
            });
        }
        return list;
    }

    public async Task UpsertStateAsync(WanHealthState s, CancellationToken ct = default)
    {
        const string sql = @"
            INSERT INTO wan_health_state
                (interface_id, is_up, consecutive_failures, consecutive_successes,
                 last_check_at, last_transition_at, last_rtt_ms, last_target, last_error)
            VALUES (@i, @up, @cf, @cs, @lc, @lt, @rtt, @tgt, @err)
            ON CONFLICT (interface_id) DO UPDATE SET
                is_up                 = EXCLUDED.is_up,
                consecutive_failures  = EXCLUDED.consecutive_failures,
                consecutive_successes = EXCLUDED.consecutive_successes,
                last_check_at         = EXCLUDED.last_check_at,
                last_transition_at    = EXCLUDED.last_transition_at,
                last_rtt_ms           = EXCLUDED.last_rtt_ms,
                last_target           = EXCLUDED.last_target,
                last_error            = EXCLUDED.last_error";
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("i",   s.InterfaceId);
        cmd.Parameters.AddWithValue("up",  s.IsUp);
        cmd.Parameters.AddWithValue("cf",  s.ConsecutiveFailures);
        cmd.Parameters.AddWithValue("cs",  s.ConsecutiveSuccesses);
        cmd.Parameters.AddWithValue("lc",  s.LastCheckAt);
        cmd.Parameters.AddWithValue("lt",  s.LastTransitionAt);
        cmd.Parameters.AddWithValue("rtt", (object?)s.LastRttMs    ?? DBNull.Value);
        cmd.Parameters.AddWithValue("tgt", (object?)s.LastTarget   ?? DBNull.Value);
        cmd.Parameters.AddWithValue("err", (object?)s.LastError    ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task RecordEventAsync(Guid interfaceId, string eventType, string? detailJson, CancellationToken ct = default)
    {
        const string sql = @"
            INSERT INTO wan_health_events (interface_id, event_type, detail)
            VALUES (@i, @t, @d::jsonb)";
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("i", interfaceId);
        cmd.Parameters.AddWithValue("t", eventType);
        cmd.Parameters.AddWithValue("d", (object?)detailJson ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<IReadOnlyList<WanHealthEvent>> RecentEventsAsync(int limit = 20, CancellationToken ct = default)
    {
        const string sql = @"
            SELECT e.id, e.occurred_at, e.interface_id, e.event_type, e.detail::text, i.name
            FROM wan_health_events e
            JOIN fw_interfaces i ON i.id = e.interface_id
            ORDER BY e.occurred_at DESC
            LIMIT @lim";
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("lim", limit);
        var list = new List<WanHealthEvent>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            list.Add(new WanHealthEvent
            {
                Id            = r.GetInt64(0),
                OccurredAt    = r.GetDateTime(1),
                InterfaceId   = r.GetGuid(2),
                EventType     = r.GetString(3),
                Detail        = r.IsDBNull(4) ? null : r.GetString(4),
                InterfaceName = r.GetString(5),
            });
        }
        return list;
    }
}
