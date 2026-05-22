using System.Net;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace NetFirewall.Services.Monitoring;

public sealed class TopTalkersService : ITopTalkersService
{
    private readonly NpgsqlDataSource _ds;
    private readonly ILogger<TopTalkersService> _logger;

    // Friendly names for the most common ports. Keeps the dashboard readable
    // without dragging in a /etc/services lookup. Extend as needed.
    private static readonly Dictionary<int, string> WellKnownPorts = new()
    {
        [22]    = "ssh",
        [25]    = "smtp",
        [53]    = "dns",
        [80]    = "http",
        [110]   = "pop3",
        [143]   = "imap",
        [443]   = "https",
        [465]   = "smtps",
        [587]   = "submission",
        [993]   = "imaps",
        [995]   = "pop3s",
        [1194]  = "openvpn",
        [3306]  = "mysql",
        [3389]  = "rdp",
        [5060]  = "sip",
        [5061]  = "sips",
        [5432]  = "postgresql",
        [8080]  = "http-alt",
        [8443]  = "https-alt",
        [11434] = "ollama",
        [51820] = "wireguard",
    };

    public TopTalkersService(NpgsqlDataSource ds, ILogger<TopTalkersService> logger)
    {
        _ds = ds;
        _logger = logger;
    }

    public async Task<IReadOnlyList<TopTalkerHost>> GetTopHostsAsync(int hours, int limit, CancellationToken ct = default)
    {
        // LEFT JOIN dhcp_leases to surface the device hostname when we have a
        // lease for that IP. Falls back to NULL (UI shows just the IP).
        const string sql = @"
            SELECT s.src_ip,
                   SUM(s.bytes_in)::bigint  AS bin,
                   SUM(s.bytes_out)::bigint AS bout,
                   SUM(s.flow_count)::int   AS flows,
                   (SELECT hostname FROM dhcp_leases dl WHERE dl.ip_address = s.src_ip ORDER BY dl.end_time DESC LIMIT 1) AS hostname
            FROM lan_traffic_samples s
            WHERE s.sampled_at > now() - make_interval(hours => @hours)
            GROUP BY s.src_ip
            ORDER BY (SUM(s.bytes_in) + SUM(s.bytes_out)) DESC
            LIMIT @limit";

        var list = new List<TopTalkerHost>();
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("hours", hours);
        cmd.Parameters.AddWithValue("limit", limit);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            list.Add(new TopTalkerHost(
                SrcIp: r.GetFieldValue<IPAddress>(0),
                BytesIn: r.GetInt64(1),
                BytesOut: r.GetInt64(2),
                FlowCount: r.GetInt32(3),
                Hostname: r.IsDBNull(4) ? null : r.GetString(4)));
        }
        return list;
    }

    public async Task<IReadOnlyList<TopTalkerService>> GetTopServicesAsync(int hours, int limit, CancellationToken ct = default)
    {
        const string sql = @"
            SELECT proto,
                   dst_port,
                   SUM(bytes_in)::bigint  AS bin,
                   SUM(bytes_out)::bigint AS bout,
                   SUM(flow_count)::int   AS flows
            FROM lan_traffic_samples
            WHERE sampled_at > now() - make_interval(hours => @hours)
              AND proto IS NOT NULL
            GROUP BY proto, dst_port
            ORDER BY (SUM(bytes_in) + SUM(bytes_out)) DESC
            LIMIT @limit";

        var list = new List<TopTalkerService>();
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("hours", hours);
        cmd.Parameters.AddWithValue("limit", limit);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            var proto = r.GetString(0);
            var port = r.IsDBNull(1) ? (int?)null : r.GetInt32(1);
            list.Add(new TopTalkerService(
                Proto: proto,
                DstPort: port,
                ServiceName: port is int p && WellKnownPorts.TryGetValue(p, out var name) ? name : null,
                BytesIn: r.GetInt64(2),
                BytesOut: r.GetInt64(3),
                FlowCount: r.GetInt32(4)));
        }
        return list;
    }

    public async Task<IReadOnlyList<TopTalkerDestination>> GetTopDestinationsForHostAsync(
        IPAddress srcIp, int hours, int limit, CancellationToken ct = default)
    {
        // Sum bytes per destination for this host, then enrich each dst_ip with
        // its ASN/org from ip_asn_cache. The cache is keyed by prefix and several
        // prefixes can contain the same IP, so a LATERAL join picks the MOST
        // SPECIFIC match (longest mask). The "others" rollup row (dst_ip IS NULL)
        // carries no enrichment. NULLs sort last so real destinations rank first.
        const string sql = @"
            SELECT s.dst_ip,
                   SUM(s.bytes_in)::bigint  AS bin,
                   SUM(s.bytes_out)::bigint AS bout,
                   SUM(s.flow_count)::int   AS flows,
                   c.asn, c.org, c.country
            FROM lan_traffic_samples s
            LEFT JOIN LATERAL (
                SELECT asn, org, country
                FROM ip_asn_cache
                WHERE prefix >>= s.dst_ip AND ok
                ORDER BY masklen(prefix) DESC
                LIMIT 1
            ) c ON s.dst_ip IS NOT NULL
            WHERE s.src_ip = @src
              AND s.sampled_at > now() - make_interval(hours => @hours)
            GROUP BY s.dst_ip, c.asn, c.org, c.country
            ORDER BY (SUM(s.bytes_in) + SUM(s.bytes_out)) DESC
            LIMIT @limit";

        var list = new List<TopTalkerDestination>();
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("src", srcIp);
        cmd.Parameters.AddWithValue("hours", hours);
        cmd.Parameters.AddWithValue("limit", limit);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            list.Add(new TopTalkerDestination(
                DstIp: r.IsDBNull(0) ? null : r.GetFieldValue<IPAddress>(0),
                BytesIn: r.GetInt64(1),
                BytesOut: r.GetInt64(2),
                FlowCount: r.GetInt32(3),
                Asn: r.IsDBNull(4) ? null : r.GetString(4),
                Org: r.IsDBNull(5) ? null : r.GetString(5),
                Country: r.IsDBNull(6) ? null : r.GetString(6)));
        }
        return list;
    }
}
