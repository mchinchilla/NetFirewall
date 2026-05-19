using System.Globalization;
using System.Net;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Services.Processes;
using Npgsql;

namespace NetFirewall.Services.Monitoring;

/// <summary>
/// Hosted service that polls <c>conntrack -L</c> every ~30s, aggregates flow
/// bytes by source-IP + protocol + destination-port, and writes one row per
/// (src,proto,dport) bucket into <c>lan_traffic_samples</c>. Powers the
/// dashboard's "top talkers" panel.
///
/// <para>Why conntrack and not nft counters: counters require one rule per
/// host, which doesn't scale and forces nft regen on each new LAN device.
/// conntrack already tracks every flow with bytes; we just sample it.</para>
///
/// <para>Why deltas, not totals: <c>conntrack -L</c> reports total bytes for
/// the flow's lifetime. Two consecutive snapshots of the same flow would
/// double-count. We track per-flow last-seen bytes between samples and
/// emit only the delta. Flows that vanish between samples contribute their
/// final delta on the cycle they disappear.</para>
/// </summary>
[SupportedOSPlatform("linux")]
public sealed partial class ConntrackSamplerService : BackgroundService
{
    private readonly NpgsqlDataSource _ds;
    private readonly IProcessRunner _runner;
    private readonly ILogger<ConntrackSamplerService> _logger;
    private readonly ConntrackSamplerOptions _opts;

    // (src, dst, sport, dport, proto) → last-observed flow bytes. Lets us
    // compute deltas across sample windows.
    private readonly Dictionary<FlowKey, FlowBytes> _last = new();

    public ConntrackSamplerService(
        NpgsqlDataSource ds,
        IProcessRunner runner,
        IOptions<ConntrackSamplerOptions> opts,
        ILogger<ConntrackSamplerService> logger)
    {
        _ds = ds;
        _runner = runner;
        _opts = opts.Value;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_opts.Enabled)
        {
            _logger.LogInformation("Conntrack sampler disabled by config — exiting.");
            return;
        }

        var period = TimeSpan.FromSeconds(_opts.SampleSeconds);
        _logger.LogInformation("Conntrack sampler started — sampling every {Sec}s, LAN={Cidr}",
            _opts.SampleSeconds, _opts.LanCidr);

        // conntrack -L only emits `bytes=` when kernel-side accounting is on.
        // The flag is off by default on Debian. We can't `sysctl -w` it from
        // the daemon because the systemd unit sets ProtectKernelTunables=yes
        // (makes /proc/sys read-only inside the unit's mount namespace).
        // The right place to enable it is /etc/sysctl.d/ — handled by the
        // installer (deploy/sysctl/netfirewall.conf). We just observe and
        // warn if accounting is off so the operator can fix it.
        try
        {
            var v = await File.ReadAllTextAsync("/proc/sys/net/netfilter/nf_conntrack_acct", stoppingToken);
            if (v.Trim() == "0")
                _logger.LogWarning("net.netfilter.nf_conntrack_acct=0 — conntrack will not report byte counters " +
                    "and top-talkers will be empty. Enable with: sysctl -w net.netfilter.nf_conntrack_acct=1 " +
                    "(persist via /etc/sysctl.d/netfirewall.conf).");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not read nf_conntrack_acct — proceeding anyway");
        }

        var lan = IPNetwork.Parse(_opts.LanCidr);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await SampleOnceAsync(lan, stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "Conntrack sampling cycle failed");
            }

            try { await Task.Delay(period, stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task SampleOnceAsync(IPNetwork lan, CancellationToken ct)
    {
        // -o extended gives us "src=A dst=B sport=X dport=Y packets=N bytes=B"
        // for both directions. -p exits cleanly with no entries if conntrack
        // is empty.
        var result = await _runner.RunAsync("conntrack", "-L -o extended", TimeSpan.FromSeconds(10), ct);
        if (!result.Success)
        {
            _logger.LogWarning("conntrack -L exit {Exit}: {Err}", result.ExitCode, result.Error);
            return;
        }

        // Aggregate this snapshot by (src, proto, dport) buckets.
        var buckets = new Dictionary<BucketKey, BucketAgg>();
        var seenFlows = new HashSet<FlowKey>();

        foreach (var line in result.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!TryParseFlow(line, out var flow)) continue;

            // Skip flows where the LAN side isn't involved as source. We track
            // outbound from LAN, inbound is mirrored in the reverse tuple.
            if (!IsLanSrc(flow, lan, out var lanSrc, out var serverPort, out var proto)) continue;

            seenFlows.Add(flow.Key);

            // Per-flow delta vs last seen. If unseen, the delta is the
            // current total (flow started during this window).
            var prev = _last.TryGetValue(flow.Key, out var p) ? p : default;
            var deltaIn = Math.Max(0, flow.OutgoingBytes - prev.OutgoingBytes);
            var deltaOut = Math.Max(0, flow.IncomingBytes - prev.IncomingBytes);
            _last[flow.Key] = new FlowBytes(flow.OutgoingBytes, flow.IncomingBytes);

            if (deltaIn == 0 && deltaOut == 0) continue;

            var key = new BucketKey(lanSrc, proto, serverPort);
            if (!buckets.TryGetValue(key, out var agg))
                agg = new BucketAgg(0, 0, 0);
            buckets[key] = new BucketAgg(agg.BytesIn + deltaIn, agg.BytesOut + deltaOut, agg.Flows + 1);
        }

        // Garbage-collect flows we no longer see — prevents the dictionary
        // from growing forever as connections churn.
        var stale = _last.Keys.Where(k => !seenFlows.Contains(k)).ToList();
        foreach (var k in stale) _last.Remove(k);

        if (buckets.Count == 0) return;

        await InsertAsync(buckets, ct);
        await PruneOldAsync(ct);
    }

    private async Task InsertAsync(Dictionary<BucketKey, BucketAgg> buckets, CancellationToken ct)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        const string sql = @"
            INSERT INTO lan_traffic_samples
                (sampled_at, src_ip, proto, dst_port, bytes_in, bytes_out, flow_count)
            VALUES
                (@at, @src, @proto, @dport, @bin, @bout, @flows)";
        var now = DateTime.UtcNow;
        foreach (var (k, agg) in buckets)
        {
            await using var cmd = new NpgsqlCommand(sql, conn, tx);
            cmd.Parameters.AddWithValue("at", now);
            cmd.Parameters.AddWithValue("src", k.SrcIp);
            cmd.Parameters.AddWithValue("proto", (object?)k.Proto ?? DBNull.Value);
            cmd.Parameters.AddWithValue("dport", k.DstPort is int dp ? (object)dp : DBNull.Value);
            cmd.Parameters.AddWithValue("bin", agg.BytesIn);
            cmd.Parameters.AddWithValue("bout", agg.BytesOut);
            cmd.Parameters.AddWithValue("flows", agg.Flows);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        await tx.CommitAsync(ct);
    }

    private async Task PruneOldAsync(CancellationToken ct)
    {
        // Only prune occasionally — we don't need exactly N-day retention,
        // ballpark is fine. Runs on roughly 1 in 100 cycles (every ~50min
        // at 30s sampling).
        if (Random.Shared.Next(100) > 0) return;

        try
        {
            await using var conn = await _ds.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(
                "DELETE FROM lan_traffic_samples WHERE sampled_at < now() - INTERVAL '7 days'", conn);
            var deleted = await cmd.ExecuteNonQueryAsync(ct);
            if (deleted > 0)
                _logger.LogInformation("Pruned {N} old lan_traffic_samples rows", deleted);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "lan_traffic_samples prune failed");
        }
    }

    // ───────────────────────── conntrack parsing ─────────────────────────

    private readonly record struct FlowKey(IPAddress Src, IPAddress Dst, int SrcPort, int DstPort, string Proto);
    private readonly record struct FlowBytes(long OutgoingBytes, long IncomingBytes);
    private readonly record struct BucketKey(IPAddress SrcIp, string? Proto, int? DstPort);
    private readonly record struct BucketAgg(long BytesIn, long BytesOut, int Flows);
    private readonly record struct Flow(FlowKey Key, long OutgoingBytes, long IncomingBytes);

    private static bool TryParseFlow(string line, out Flow flow)
    {
        flow = default;

        // Sample line (conntrack-tools 1.4.x on Debian):
        //   ipv4 2 tcp 6 432000 ESTABLISHED src=192.168.99.10 dst=8.8.8.8 sport=51234 dport=443 packets=10 bytes=1234 \
        //                                    src=8.8.8.8 dst=192.168.99.10 sport=443 dport=51234 packets=8 bytes=5678 [ASSURED] mark=0 use=2
        //
        // The two halves are the forward and reply tuples. We need both bytes
        // counters. We skip ipv6 lines (`ipv6 10 ...`) — top-talkers are LAN-IPv4
        // for now.

        var protoMatch = ProtoRx().Match(line);
        if (!protoMatch.Success) return false;
        var proto = protoMatch.Groups[1].Value;
        if (proto != "tcp" && proto != "udp" && proto != "icmp") proto = "other";

        // First and second src= → forward and reply tuples.
        var srcs = SrcRx().Matches(line);
        var dsts = DstRx().Matches(line);
        var sports = SportRx().Matches(line);
        var dports = DportRx().Matches(line);
        var bytes = BytesRx().Matches(line);
        if (srcs.Count < 1 || dsts.Count < 1 || bytes.Count < 1) return false;
        if (!IPAddress.TryParse(srcs[0].Groups[1].Value, out var src)) return false;
        if (!IPAddress.TryParse(dsts[0].Groups[1].Value, out var dst)) return false;

        int sport = 0, dport = 0;
        if (sports.Count > 0) int.TryParse(sports[0].Groups[1].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out sport);
        if (dports.Count > 0) int.TryParse(dports[0].Groups[1].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out dport);

        long bytesFwd = 0, bytesRev = 0;
        long.TryParse(bytes[0].Groups[1].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out bytesFwd);
        if (bytes.Count > 1)
            long.TryParse(bytes[1].Groups[1].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out bytesRev);

        flow = new Flow(
            new FlowKey(src, dst, sport, dport, proto),
            bytesFwd,
            bytesRev);
        return true;
    }

    private static bool IsLanSrc(Flow flow, IPNetwork lan, out IPAddress lanSrc, out int? serverPort, out string proto)
    {
        lanSrc = flow.Key.Src;
        serverPort = null;
        proto = flow.Key.Proto;

        // Both src and dst could be in LAN (intra-LAN traffic). We only want
        // outbound flows for top-talkers (else everything double-counts).
        var srcInLan = lan.Contains(flow.Key.Src);
        var dstInLan = lan.Contains(flow.Key.Dst);
        if (!srcInLan || dstInLan) return false;

        // Heuristic: "server" port is the lower of the two — well-known ports
        // are < 1024 and ephemeral start at 32768. Works for HTTPS/HTTP/SIP/DNS.
        if (flow.Key.SrcPort > 0 && flow.Key.DstPort > 0)
            serverPort = Math.Min(flow.Key.SrcPort, flow.Key.DstPort);
        else if (flow.Key.DstPort > 0)
            serverPort = flow.Key.DstPort;

        return true;
    }

    // Matches the L4 protocol token. Handles both modern conntrack-tools output
    // ("ipv4 2 tcp 6 ...") and the older bare form ("tcp 6 ..."). The leading
    // `ipv4 <num>` is optional. Skips ipv6 (not tracked yet).
    [GeneratedRegex(@"^\s*(?:ipv4\s+\d+\s+)?(tcp|udp|icmp|other)\s+\d+")] private static partial Regex ProtoRx();
    [GeneratedRegex(@"\bsrc=([\d.]+)")]    private static partial Regex SrcRx();
    [GeneratedRegex(@"\bdst=([\d.]+)")]    private static partial Regex DstRx();
    [GeneratedRegex(@"\bsport=(\d+)")]     private static partial Regex SportRx();
    [GeneratedRegex(@"\bdport=(\d+)")]     private static partial Regex DportRx();
    [GeneratedRegex(@"\bbytes=(\d+)")]     private static partial Regex BytesRx();
}

public sealed class ConntrackSamplerOptions
{
    public const string SectionName = "ConntrackSampler";

    /// <summary>Disable in dev or on hosts without conntrack-tools installed.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>How often to snapshot conntrack. 30s balances accuracy vs DB churn.</summary>
    public int SampleSeconds { get; set; } = 30;

    /// <summary>LAN CIDR — flows whose src isn't in this range are ignored.</summary>
    public string LanCidr { get; set; } = "192.168.99.0/24";
}
