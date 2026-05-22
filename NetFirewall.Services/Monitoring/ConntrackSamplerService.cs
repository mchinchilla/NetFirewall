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
    private readonly ILocalAddressProvider _localAddresses;
    private readonly IIpAsnResolver _asnResolver;
    private readonly ILogger<ConntrackSamplerService> _logger;
    private readonly ConntrackSamplerOptions _opts;

    // (src, dst, sport, dport, proto) → last-observed flow bytes. Lets us
    // compute deltas across sample windows.
    private readonly Dictionary<FlowKey, FlowBytes> _last = new();

    // The firewall's own IPs — destinations matching these are NAT reply tuples
    // leaking our WAN IP, not real egress. Snapshotted at startup.
    private IReadOnlySet<IPAddress> _ownIps = new HashSet<IPAddress>();

    public ConntrackSamplerService(
        NpgsqlDataSource ds,
        IProcessRunner runner,
        ILocalAddressProvider localAddresses,
        IIpAsnResolver asnResolver,
        IOptions<ConntrackSamplerOptions> opts,
        ILogger<ConntrackSamplerService> logger)
    {
        _ds = ds;
        _runner = runner;
        _localAddresses = localAddresses;
        _asnResolver = asnResolver;
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

        // Snapshot our own IPs once at startup so SNAT reply tuples (which carry
        // our WAN IP as dst) are never recorded as a traffic destination.
        _ownIps = _localAddresses.GetLocalAddresses();
        _logger.LogInformation("Conntrack sampler: {N} local addresses excluded as destinations: {Ips}",
            _ownIps.Count, string.Join(", ", _ownIps));

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

        // Aggregate this snapshot by (src, dst, proto, dport) buckets.
        var buckets = new Dictionary<BucketKey, BucketAgg>();
        var seenFlows = new HashSet<FlowKey>();

        foreach (var line in result.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!TryParseFlow(line, out var flow)) continue;

            // Keep only outbound flows initiated by a LAN host, attributed to the
            // real (forward-tuple) destination and the port the host connected to.
            if (!ClassifyFlow(flow, lan, _ownIps, out var lanSrc, out var dstIp, out var serverPort, out var proto)) continue;

            seenFlows.Add(flow.Key);

            // Per-flow delta vs last seen. If unseen, the delta is the
            // current total (flow started during this window).
            var prev = _last.TryGetValue(flow.Key, out var p) ? p : default;
            var deltaIn = Math.Max(0, flow.OutgoingBytes - prev.OutgoingBytes);
            var deltaOut = Math.Max(0, flow.IncomingBytes - prev.IncomingBytes);
            _last[flow.Key] = new FlowBytes(flow.OutgoingBytes, flow.IncomingBytes);

            if (deltaIn == 0 && deltaOut == 0) continue;

            var key = new BucketKey(lanSrc, dstIp, proto, serverPort);
            if (!buckets.TryGetValue(key, out var agg))
                agg = new BucketAgg(0, 0, 0);
            buckets[key] = new BucketAgg(agg.BytesIn + deltaIn, agg.BytesOut + deltaOut, agg.Flows + 1);

            // Off-hot-path enrichment: queue the destination for ASN lookup.
            _asnResolver.Enqueue(dstIp);
        }

        // Garbage-collect flows we no longer see — prevents the dictionary
        // from growing forever as connections churn.
        var stale = _last.Keys.Where(k => !seenFlows.Contains(k)).ToList();
        foreach (var k in stale) _last.Remove(k);

        if (buckets.Count == 0) return;

        // Cap per-host cardinality: keep the heaviest N destinations per host,
        // fold the tail into one rollup row (dst_ip NULL). A chatty host can talk
        // to thousands of IPs/day; without this the table explodes.
        var capped = ApplyTopNPerHost(buckets, _opts.TopDestinationsPerHost);

        await InsertAsync(capped, ct);
        await PruneOldAsync(ct);
    }

    /// <summary>
    /// Per host (src_ip), keep the <paramref name="topN"/> destinations with the
    /// most total bytes and merge everything else into a single bucket with
    /// DstIp = null (the "others" rollup). Pure function — unit-testable.
    /// </summary>
    internal static Dictionary<BucketKey, BucketAgg> ApplyTopNPerHost(
        Dictionary<BucketKey, BucketAgg> buckets, int topN)
    {
        if (topN <= 0) return buckets;

        var result = new Dictionary<BucketKey, BucketAgg>();
        foreach (var byHost in buckets.GroupBy(kv => kv.Key.SrcIp))
        {
            // Rank this host's (dst,proto,port) buckets by total bytes desc.
            var ranked = byHost
                .OrderByDescending(kv => kv.Value.BytesIn + kv.Value.BytesOut)
                .ToList();

            foreach (var kv in ranked.Take(topN))
                result[kv.Key] = kv.Value;

            // Fold the tail into one rollup keyed (host, null dst, null proto/port).
            var tail = ranked.Skip(topN).ToList();
            if (tail.Count == 0) continue;

            var rollupKey = new BucketKey(byHost.Key, null, null, null);
            long bin = 0, bout = 0; int flows = 0;
            foreach (var kv in tail)
            {
                bin += kv.Value.BytesIn;
                bout += kv.Value.BytesOut;
                flows += kv.Value.Flows;
            }
            result[rollupKey] = new BucketAgg(bin, bout, flows);
        }
        return result;
    }

    private async Task InsertAsync(Dictionary<BucketKey, BucketAgg> buckets, CancellationToken ct)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        const string sql = @"
            INSERT INTO lan_traffic_samples
                (sampled_at, src_ip, dst_ip, proto, dst_port, bytes_in, bytes_out, flow_count)
            VALUES
                (@at, @src, @dst, @proto, @dport, @bin, @bout, @flows)";
        var now = DateTime.UtcNow;
        foreach (var (k, agg) in buckets)
        {
            await using var cmd = new NpgsqlCommand(sql, conn, tx);
            cmd.Parameters.AddWithValue("at", now);
            cmd.Parameters.AddWithValue("src", k.SrcIp);
            cmd.Parameters.AddWithValue("dst", (object?)k.DstIp ?? DBNull.Value);
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

    internal readonly record struct FlowKey(IPAddress Src, IPAddress Dst, int SrcPort, int DstPort, string Proto);
    private readonly record struct FlowBytes(long OutgoingBytes, long IncomingBytes);
    // DstIp NULL = the per-host "others" rollup bucket (tail beyond Top-N).
    internal readonly record struct BucketKey(IPAddress SrcIp, IPAddress? DstIp, string? Proto, int? DstPort);
    internal readonly record struct BucketAgg(long BytesIn, long BytesOut, int Flows);
    internal readonly record struct Flow(FlowKey Key, long OutgoingBytes, long IncomingBytes);

    internal static bool TryParseFlow(string line, out Flow flow)
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

    /// <summary>
    /// Decides whether a parsed conntrack flow counts as outbound LAN traffic and,
    /// if so, what to attribute it to. Pure function — no IO, fully unit-testable.
    /// </summary>
    /// <param name="flow">Parsed flow. <c>flow.Key</c> holds the FORWARD tuple
    /// (src=connection initiator, dst=real pre-NAT destination, dport=service port).</param>
    /// <param name="lan">Configured LAN network.</param>
    /// <param name="ownIps">The firewall's own IP addresses (all interfaces +
    /// loopback). A flow whose recorded destination is one of these is the NAT
    /// reply tuple leaking our WAN IP, or host-bound traffic — not a real egress
    /// destination, so we reject it.</param>
    /// <param name="lanSrc">The LAN source IP (the top-talker host).</param>
    /// <param name="dstIp">The REAL destination (forward-tuple dst), for per-dest
    /// accounting. Never the reply tuple's dst (= our WAN IP).</param>
    /// <param name="serverPort">The service port the LAN host connected to
    /// (forward-tuple dport), or null when neither side has a meaningful port.</param>
    /// <param name="proto">L4 protocol.</param>
    internal static bool ClassifyFlow(
        Flow flow, IPNetwork lan, IReadOnlySet<IPAddress> ownIps,
        out IPAddress lanSrc, out IPAddress dstIp, out int? serverPort, out string proto)
    {
        lanSrc = flow.Key.Src;
        dstIp = flow.Key.Dst;
        serverPort = null;
        proto = flow.Key.Proto;

        // We only want outbound flows initiated by a LAN host. Reject if the
        // source isn't in the LAN, or if the destination is also internal —
        // intra-LAN traffic, the firewall's own IPs (NAT reply tuple carries our
        // WAN IP as dst after SNAT), or any RFC1918 address. Counting those
        // double-counts and pollutes per-destination stats with our own address.
        if (!lan.Contains(flow.Key.Src)) return false;
        if (lan.Contains(dstIp) || ownIps.Contains(dstIp) || IpRanges.IsPrivate(dstIp)) return false;

        // The service port is the port the LAN host CONNECTED TO — i.e. the
        // forward tuple's dport. (Old code used Math.Min(sport,dport), which
        // mislabels media/ephemeral-vs-ephemeral flows with a bogus high port.)
        // dport==0 (e.g. ICMP) → null, "no service attribution".
        if (flow.Key.DstPort > 0) serverPort = flow.Key.DstPort;

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

    /// <summary>Max distinct destinations recorded per host per sample window;
    /// the tail is folded into one "others" rollup row (dst_ip NULL). 0 = unlimited.</summary>
    public int TopDestinationsPerHost { get; set; } = 20;
}
