using NetFirewall.Models.Vpn;
using Npgsql;

namespace NetFirewall.Services.Vpn;

/// <summary>
/// Npgsql-backed implementation of <see cref="IVpnHealthService"/>. Direct
/// parameterized SQL (same style as <c>WanHealthService</c>) — no RepoDb here
/// because the reads join across wg_peers/wg_servers for denormalized names.
/// </summary>
public sealed class VpnHealthService : IVpnHealthService
{
    private readonly NpgsqlDataSource _ds;

    public VpnHealthService(NpgsqlDataSource ds) => _ds = ds;

    public async Task<IReadOnlyList<VpnHealthState>> GetStateAsync(CancellationToken ct = default)
    {
        // LEFT JOIN wg_peers: a state row can exist for a pubkey with no catalog
        // row (imported/desynced peer) — COALESCE to a readable fallback name.
        const string sql = @"
            SELECT s.server_id, s.public_key, s.is_up, s.consecutive_failures,
                   s.consecutive_successes, s.last_check_at, s.last_transition_at,
                   s.last_handshake_at, s.last_endpoint,
                   COALESCE(p.name, '(unknown)'), COALESCE(srv.name, '')
            FROM vpn_health_state s
            JOIN wg_servers srv ON srv.id = s.server_id
            LEFT JOIN wg_peers p ON p.server_id = s.server_id AND p.public_key = s.public_key
            ORDER BY srv.name, p.name";
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        var list = new List<VpnHealthState>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            list.Add(new VpnHealthState
            {
                ServerId              = r.GetGuid(0),
                PublicKey             = r.GetString(1),
                IsUp                  = r.GetBoolean(2),
                ConsecutiveFailures   = r.GetInt32(3),
                ConsecutiveSuccesses  = r.GetInt32(4),
                LastCheckAt           = r.GetDateTime(5),
                LastTransitionAt      = r.GetDateTime(6),
                LastHandshakeAt       = r.IsDBNull(7) ? null : r.GetDateTime(7),
                LastEndpoint          = r.IsDBNull(8) ? null : r.GetString(8),
                PeerName              = r.GetString(9),
                ServerName            = r.GetString(10),
            });
        }
        return list;
    }

    public async Task UpsertStateAsync(VpnHealthState s, CancellationToken ct = default)
    {
        const string sql = @"
            INSERT INTO vpn_health_state
                (server_id, public_key, is_up, consecutive_failures, consecutive_successes,
                 last_check_at, last_transition_at, last_handshake_at, last_endpoint)
            VALUES (@srv, @pk, @up, @cf, @cs, @lc, @lt, @lh, @ep)
            ON CONFLICT (server_id, public_key) DO UPDATE SET
                is_up                 = EXCLUDED.is_up,
                consecutive_failures  = EXCLUDED.consecutive_failures,
                consecutive_successes = EXCLUDED.consecutive_successes,
                last_check_at         = EXCLUDED.last_check_at,
                last_transition_at    = EXCLUDED.last_transition_at,
                last_handshake_at     = EXCLUDED.last_handshake_at,
                last_endpoint         = EXCLUDED.last_endpoint";
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("srv", s.ServerId);
        cmd.Parameters.AddWithValue("pk",  s.PublicKey);
        cmd.Parameters.AddWithValue("up",  s.IsUp);
        cmd.Parameters.AddWithValue("cf",  s.ConsecutiveFailures);
        cmd.Parameters.AddWithValue("cs",  s.ConsecutiveSuccesses);
        cmd.Parameters.AddWithValue("lc",  s.LastCheckAt);
        cmd.Parameters.AddWithValue("lt",  s.LastTransitionAt);
        cmd.Parameters.AddWithValue("lh",  (object?)s.LastHandshakeAt ?? DBNull.Value);
        cmd.Parameters.AddWithValue("ep",  (object?)s.LastEndpoint    ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task RecordEventAsync(Guid serverId, string publicKey, string eventType, string? detailJson, CancellationToken ct = default)
    {
        const string sql = @"
            INSERT INTO vpn_health_events (server_id, public_key, event_type, detail)
            VALUES (@srv, @pk, @t, @d::jsonb)";
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("srv", serverId);
        cmd.Parameters.AddWithValue("pk",  publicKey);
        cmd.Parameters.AddWithValue("t",   eventType);
        cmd.Parameters.AddWithValue("d",   (object?)detailJson ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<IReadOnlyList<VpnHealthEvent>> RecentEventsAsync(int limit = 20, CancellationToken ct = default)
    {
        const string sql = @"
            SELECT e.id, e.occurred_at, e.server_id, e.public_key, e.event_type, e.detail::text,
                   COALESCE(p.name, '(unknown)'), COALESCE(srv.name, '')
            FROM vpn_health_events e
            JOIN wg_servers srv ON srv.id = e.server_id
            LEFT JOIN wg_peers p ON p.server_id = e.server_id AND p.public_key = e.public_key
            ORDER BY e.occurred_at DESC
            LIMIT @lim";
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("lim", limit);
        var list = new List<VpnHealthEvent>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            list.Add(new VpnHealthEvent
            {
                Id          = r.GetInt64(0),
                OccurredAt  = r.GetDateTime(1),
                ServerId    = r.GetGuid(2),
                PublicKey   = r.GetString(3),
                EventType   = r.GetString(4),
                Detail      = r.IsDBNull(5) ? null : r.GetString(5),
                PeerName    = r.GetString(6),
                ServerName  = r.GetString(7),
            });
        }
        return list;
    }

    public async Task RaiseAlertAsync(SystemAlert a, CancellationToken ct = default)
    {
        // Upsert by dedupe_key. If a row already exists we refresh its content and
        // CLEAR resolved_at (re-arming it), but keep the original raised_at so the
        // banner shows how long the condition has actually been active.
        const string sql = @"
            INSERT INTO system_alerts (source, severity, dedupe_key, title, body)
            VALUES (@src, @sev, @key, @title, @body)
            ON CONFLICT (dedupe_key) DO UPDATE SET
                source      = EXCLUDED.source,
                severity    = EXCLUDED.severity,
                title       = EXCLUDED.title,
                body        = EXCLUDED.body,
                resolved_at = NULL,
                raised_at   = CASE WHEN system_alerts.resolved_at IS NULL
                                   THEN system_alerts.raised_at ELSE now() END";
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("src",   a.Source);
        cmd.Parameters.AddWithValue("sev",   a.Severity);
        cmd.Parameters.AddWithValue("key",   a.DedupeKey);
        cmd.Parameters.AddWithValue("title", a.Title);
        cmd.Parameters.AddWithValue("body",  (object?)a.Body ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task ResolveAlertAsync(string dedupeKey, CancellationToken ct = default)
    {
        const string sql = @"
            UPDATE system_alerts SET resolved_at = now()
            WHERE dedupe_key = @key AND resolved_at IS NULL";
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("key", dedupeKey);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<IReadOnlyList<SystemAlert>> ActiveAlertsAsync(CancellationToken ct = default)
    {
        const string sql = @"
            SELECT id, source, severity, dedupe_key, title, body, raised_at, resolved_at
            FROM system_alerts
            WHERE resolved_at IS NULL
            ORDER BY raised_at DESC";
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        var list = new List<SystemAlert>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            list.Add(new SystemAlert
            {
                Id         = r.GetInt64(0),
                Source     = r.GetString(1),
                Severity   = r.GetString(2),
                DedupeKey  = r.GetString(3),
                Title      = r.GetString(4),
                Body       = r.IsDBNull(5) ? null : r.GetString(5),
                RaisedAt   = r.GetDateTime(6),
                ResolvedAt = r.IsDBNull(7) ? null : r.GetDateTime(7),
            });
        }
        return list;
    }
}
