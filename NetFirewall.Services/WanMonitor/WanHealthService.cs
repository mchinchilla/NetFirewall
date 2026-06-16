using Microsoft.Extensions.Logging;
using NetFirewall.Models.WanMonitor;
using NetFirewall.Services.Database;
using Npgsql;

namespace NetFirewall.Services.WanMonitor;

public sealed class WanHealthService : IWanHealthService
{
    private readonly NpgsqlDataSource _ds;
    private readonly ILogger<WanHealthService> _logger;

    public WanHealthService(NpgsqlDataSource ds, ILogger<WanHealthService> logger)
    {
        _ds = ds;
        _logger = logger;
    }

    // Reads degrade to empty and writes become no-ops when the wan_health_*
    // tables don't exist yet (host's migrations behind the code) — see
    // MissingTableGuard. Keeps the monitor loop and dashboard alive instead of
    // throwing 42P01 on every cycle.

    public Task<IReadOnlyList<WanHealthConfig>> GetConfigsAsync(CancellationToken ct = default) =>
        MissingTableGuard.ReadListAsync(() => GetConfigsCoreAsync(ct), _logger, nameof(GetConfigsAsync));

    private async Task<IReadOnlyList<WanHealthConfig>> GetConfigsCoreAsync(CancellationToken ct)
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

    public Task<IReadOnlyList<WanHealthState>> GetStateAsync(CancellationToken ct = default) =>
        MissingTableGuard.ReadListAsync(() => GetStateCoreAsync(ct), _logger, nameof(GetStateAsync));

    private async Task<IReadOnlyList<WanHealthState>> GetStateCoreAsync(CancellationToken ct)
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

    public Task UpsertStateAsync(WanHealthState s, CancellationToken ct = default) =>
        MissingTableGuard.WriteAsync(() => UpsertStateCoreAsync(s, ct), _logger, nameof(UpsertStateAsync));

    private async Task UpsertStateCoreAsync(WanHealthState s, CancellationToken ct)
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

    public Task RecordEventAsync(Guid interfaceId, string eventType, string? detailJson, CancellationToken ct = default) =>
        MissingTableGuard.WriteAsync(() => RecordEventCoreAsync(interfaceId, eventType, detailJson, ct), _logger, nameof(RecordEventAsync));

    private async Task RecordEventCoreAsync(Guid interfaceId, string eventType, string? detailJson, CancellationToken ct)
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

    public Task<IReadOnlyList<WanHealthEvent>> RecentEventsAsync(int limit = 20, CancellationToken ct = default) =>
        MissingTableGuard.ReadListAsync(() => RecentEventsCoreAsync(limit, ct), _logger, nameof(RecentEventsAsync));

    private async Task<IReadOnlyList<WanHealthEvent>> RecentEventsCoreAsync(int limit, CancellationToken ct)
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

    // ───────────── failover control (active WAN + sticky override) ─────────────

    public async Task<WanFailoverControl> GetControlAsync(CancellationToken ct = default)
    {
        // The control row degrades to an empty (auto-mode) control if the table
        // is missing — never throws, so the UI keeps rendering.
        try
        {
            const string sql = @"
                SELECT c.override_interface_id, c.override_set_by, c.override_set_at,
                       c.active_interface_id, c.active_since,
                       oi.name, ai.name
                FROM wan_failover_control c
                LEFT JOIN fw_interfaces oi ON oi.id = c.override_interface_id
                LEFT JOIN fw_interfaces ai ON ai.id = c.active_interface_id
                WHERE c.id = true";
            await using var conn = await _ds.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            await using var r = await cmd.ExecuteReaderAsync(ct);
            if (await r.ReadAsync(ct))
            {
                return new WanFailoverControl
                {
                    OverrideInterfaceId   = r.IsDBNull(0) ? null : r.GetGuid(0),
                    OverrideSetBy         = r.IsDBNull(1) ? null : r.GetString(1),
                    OverrideSetAt         = r.IsDBNull(2) ? null : r.GetDateTime(2),
                    ActiveInterfaceId     = r.IsDBNull(3) ? null : r.GetGuid(3),
                    ActiveSince           = r.IsDBNull(4) ? null : r.GetDateTime(4),
                    OverrideInterfaceName = r.IsDBNull(5) ? null : r.GetString(5),
                    ActiveInterfaceName   = r.IsDBNull(6) ? null : r.GetString(6),
                };
            }
            return new WanFailoverControl();
        }
        catch (Exception ex) when (ex is Npgsql.PostgresException pg && pg.SqlState == MissingTableGuard.UndefinedTable)
        {
            _logger.LogWarning("GetControlAsync: wan_failover_control missing ({Sql}) — auto mode. Migration pending?", MissingTableGuard.UndefinedTable);
            return new WanFailoverControl();
        }
    }

    public Task SetOverrideAsync(Guid? interfaceId, string? setBy, CancellationToken ct = default) =>
        MissingTableGuard.WriteAsync(() => SetOverrideCoreAsync(interfaceId, setBy, ct), _logger, nameof(SetOverrideAsync));

    private async Task SetOverrideCoreAsync(Guid? interfaceId, string? setBy, CancellationToken ct)
    {
        const string sql = @"
            UPDATE wan_failover_control SET
                override_interface_id = @i,
                override_set_by       = @by,
                override_set_at       = CASE WHEN @i IS NULL THEN NULL ELSE now() END,
                updated_at            = now()
            WHERE id = true";
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("i",  (object?)interfaceId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("by", (object?)setBy ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public Task SetActiveAsync(Guid interfaceId, CancellationToken ct = default) =>
        MissingTableGuard.WriteAsync(() => SetActiveCoreAsync(interfaceId, ct), _logger, nameof(SetActiveAsync));

    private async Task SetActiveCoreAsync(Guid interfaceId, CancellationToken ct)
    {
        // Only bump active_since when the active interface actually changes, so
        // the UI's "active since" reflects the last real switch, not every tick.
        const string sql = @"
            UPDATE wan_failover_control SET
                active_since       = CASE WHEN active_interface_id IS DISTINCT FROM @i THEN now() ELSE active_since END,
                active_interface_id = @i,
                updated_at         = now()
            WHERE id = true";
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("i", interfaceId);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    // ───────────── config CRUD ─────────────

    public Task<IReadOnlyList<WanHealthConfig>> GetAllConfigsAsync(CancellationToken ct = default) =>
        MissingTableGuard.ReadListAsync(() => GetAllConfigsCoreAsync(ct), _logger, nameof(GetAllConfigsAsync));

    private async Task<IReadOnlyList<WanHealthConfig>> GetAllConfigsCoreAsync(CancellationToken ct)
    {
        // Like GetConfigsAsync but includes disabled rows and disabled interfaces
        // — the admin UI needs to see and toggle everything.
        const string sql = @"
            SELECT c.id, c.interface_id, c.priority, c.monitor_targets,
                   c.failover_threshold, c.recovery_threshold, c.enabled,
                   c.created_at, c.updated_at, i.name, c.probe_fwmark
            FROM wan_health_config c
            JOIN fw_interfaces i ON i.id = c.interface_id
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

    public Task UpsertConfigAsync(WanHealthConfig c, CancellationToken ct = default) =>
        MissingTableGuard.WriteAsync(() => UpsertConfigCoreAsync(c, ct), _logger, nameof(UpsertConfigAsync));

    private async Task UpsertConfigCoreAsync(WanHealthConfig c, CancellationToken ct)
    {
        const string sql = @"
            INSERT INTO wan_health_config
                (interface_id, priority, monitor_targets, probe_fwmark,
                 failover_threshold, recovery_threshold, enabled)
            VALUES (@i, @prio, @targets, @mark, @ft, @rt, @en)
            ON CONFLICT (interface_id) DO UPDATE SET
                priority           = EXCLUDED.priority,
                monitor_targets    = EXCLUDED.monitor_targets,
                probe_fwmark       = EXCLUDED.probe_fwmark,
                failover_threshold = EXCLUDED.failover_threshold,
                recovery_threshold = EXCLUDED.recovery_threshold,
                enabled            = EXCLUDED.enabled,
                updated_at         = now()";
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("i",       c.InterfaceId);
        cmd.Parameters.AddWithValue("prio",    c.Priority);
        cmd.Parameters.AddWithValue("targets", c.MonitorTargets ?? Array.Empty<string>());
        cmd.Parameters.AddWithValue("mark",    (object?)c.ProbeFwmark ?? DBNull.Value);
        cmd.Parameters.AddWithValue("ft",      c.FailoverThreshold);
        cmd.Parameters.AddWithValue("rt",      c.RecoveryThreshold);
        cmd.Parameters.AddWithValue("en",      c.Enabled);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
