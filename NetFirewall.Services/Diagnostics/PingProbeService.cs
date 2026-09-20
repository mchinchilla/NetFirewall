using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.Diagnostics;

public sealed partial class PingProbeService : IPingProbeService
{
    private readonly IProcessRunner _runner;
    private readonly DiagnosticsOptions _opts;
    private readonly ILogger<PingProbeService> _logger;

    public PingProbeService(IProcessRunner runner, IOptions<DiagnosticsOptions> opts, ILogger<PingProbeService> logger)
    {
        _runner = runner;
        _opts = opts.Value;
        _logger = logger;
    }

    public async Task<string?> ResolveAsync(string host, CancellationToken ct = default)
    {
        if (IPAddress.TryParse(host, out var literal)) return literal.ToString();
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(3));
            var addrs = await Dns.GetHostAddressesAsync(host, cts.Token);
            var pick = addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                       ?? addrs.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetworkV6);
            return pick?.ToString();
        }
        catch (Exception ex) when (ex is SocketException or OperationCanceledException)
        {
            _logger.LogDebug("resolve {Host} failed: {Error}", host, ex.Message);
            return null;
        }
    }

    public async Task<PingResult> PingAsync(string targetIp, string? iface, long fwmark, int count, int timeoutSec, CancellationToken ct = default)
    {
        var via = Via(iface, fwmark);
        var args = new List<string> { "-n", "-c", count.ToString(CultureInfo.InvariantCulture), "-W", timeoutSec.ToString(CultureInfo.InvariantCulture) };
        AddSteering(args, iface, fwmark);
        args.Add(targetIp);

        var budget = TimeSpan.FromSeconds(count * (timeoutSec + 1) + 3);
        var run = await _runner.RunAsync(_opts.PingPath, args, budget, ct);
        return ParsePing(targetIp, via, run.Output, run.Error, run.ExitCode);
    }

    public async Task<TracerouteResult> TracerouteAsync(string targetIp, string? iface, long fwmark, int maxHops, int timeoutSec, CancellationToken ct = default)
    {
        var via = Via(iface, fwmark);
        if (fwmark <= 0)
        {
            var args = new List<string> { "-n", "-q", "1", "-w", timeoutSec.ToString(CultureInfo.InvariantCulture), "-m", maxHops.ToString(CultureInfo.InvariantCulture) };
            if (!string.IsNullOrEmpty(iface)) { args.Add("-i"); args.Add(iface); }
            args.Add(targetIp);
            var run = await _runner.RunAsync(_opts.TraceroutePath, args, TimeSpan.FromSeconds(maxHops * (timeoutSec + 1) + 3), ct);
            if (run.ExitCode == -1 || (!run.Success && string.IsNullOrWhiteSpace(run.Output)))
                return new TracerouteResult(targetIp, via, Array.Empty<TracerouteHop>(), false, run.Output, FirstLine(run.Error) ?? "traceroute failed");
            return ParseTraceroute(targetIp, via, run.Output);
        }

        // Marked path: ping with increasing TTL. "Time to live exceeded" names the hop.
        var hops = new List<TracerouteHop>();
        var raw = new System.Text.StringBuilder();
        var reached = false;
        for (var ttl = 1; ttl <= maxHops && !reached; ttl++)
        {
            ct.ThrowIfCancellationRequested();
            var args = new List<string> { "-n", "-c", "1", "-W", timeoutSec.ToString(CultureInfo.InvariantCulture), "-t", ttl.ToString(CultureInfo.InvariantCulture), "-m", fwmark.ToString(CultureInfo.InvariantCulture), targetIp };
            var run = await _runner.RunAsync(_opts.PingPath, args, TimeSpan.FromSeconds(timeoutSec + 2), ct);
            raw.Append(run.Output);
            if (run.ExitCode == -1) return new TracerouteResult(targetIp, via, hops, false, raw.ToString(), FirstLine(run.Error) ?? "ping failed");

            var reply = ReplyRx().Match(run.Output);
            if (reply.Success)
            {
                hops.Add(new TracerouteHop(ttl, targetIp, null, [double.Parse(reply.Groups[3].Value, CultureInfo.InvariantCulture)]));
                reached = true;
                break;
            }
            var exceeded = TtlExceededRx().Match(run.Output);
            hops.Add(exceeded.Success
                ? new TracerouteHop(ttl, exceeded.Groups[1].Value, null, Array.Empty<double>())
                : new TracerouteHop(ttl, null, null, Array.Empty<double>()));
        }
        return new TracerouteResult(targetIp, via, hops, reached, raw.ToString());
    }

    // ───────────────────────── parsing (pure) ─────────────────────────

    internal static PingResult ParsePing(string target, string via, string stdout, string stderr, int exitCode)
    {
        var replies = ReplyRx().Matches(stdout)
            .Select(m => new PingReply(
                int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture),
                m.Groups[2].Success ? int.Parse(m.Groups[2].Value, CultureInfo.InvariantCulture) : null,
                double.Parse(m.Groups[3].Value, CultureInfo.InvariantCulture)))
            .ToList();

        var sent = 0; var received = 0; double loss = 100;
        var summary = SummaryRx().Match(stdout);
        if (summary.Success)
        {
            sent = int.Parse(summary.Groups[1].Value, CultureInfo.InvariantCulture);
            received = int.Parse(summary.Groups[2].Value, CultureInfo.InvariantCulture);
            loss = double.Parse(summary.Groups[3].Value, CultureInfo.InvariantCulture);
        }
        else if (replies.Count > 0)
        {
            sent = received = replies.Count; loss = 0;
        }

        double? min = null, avg = null, max = null;
        var rtt = RttRx().Match(stdout);
        if (rtt.Success)
        {
            min = double.Parse(rtt.Groups[1].Value, CultureInfo.InvariantCulture);
            avg = double.Parse(rtt.Groups[2].Value, CultureInfo.InvariantCulture);
            max = double.Parse(rtt.Groups[3].Value, CultureInfo.InvariantCulture);
        }

        // exit 2 = ping could not even try (unknown host, permission, bad option); 1 = no replies.
        var error = exitCode == 2 || exitCode == -1 ? (FirstLine(stderr) ?? "ping failed") : null;
        return new PingResult(target, target, via, sent, received, loss, min, avg, max, replies, stdout, error);
    }

    internal static TracerouteResult ParseTraceroute(string target, string via, string stdout)
    {
        var hops = new List<TracerouteHop>();
        foreach (var line in stdout.Split('\n'))
        {
            var m = HopRx().Match(line);
            if (!m.Success) continue;
            var hop = int.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
            if (m.Groups[2].Value == "*")
            {
                hops.Add(new TracerouteHop(hop, null, null, Array.Empty<double>()));
                continue;
            }
            var rtts = RttValueRx().Matches(line).Select(r => double.Parse(r.Groups[1].Value, CultureInfo.InvariantCulture)).ToList();
            hops.Add(new TracerouteHop(hop, m.Groups[2].Value, null, rtts));
        }
        var reached = hops.Count > 0 && hops[^1].Ip == target;
        return new TracerouteResult(target, via, hops, reached, stdout);
    }

    private static string Via(string? iface, long fwmark) =>
        fwmark > 0 ? $"fwmark 0x{fwmark:x}" : !string.IsNullOrEmpty(iface) ? $"iface {iface}" : "default route";

    private static void AddSteering(List<string> args, string? iface, long fwmark)
    {
        if (fwmark > 0) { args.Add("-m"); args.Add(fwmark.ToString(CultureInfo.InvariantCulture)); }
        else if (!string.IsNullOrEmpty(iface)) { args.Add("-I"); args.Add(iface); }
    }

    private static string? FirstLine(string? s) =>
        string.IsNullOrWhiteSpace(s) ? null : s.Split('\n', StringSplitOptions.RemoveEmptyEntries)[0].Trim();

    [GeneratedRegex(@"icmp_seq=(\d+)(?:\s+ttl=(\d+))?\s+time=([\d.]+)\s*ms")]
    private static partial Regex ReplyRx();

    [GeneratedRegex(@"(\d+) packets transmitted, (\d+) (?:packets )?received.*?([\d.]+)% packet loss")]
    private static partial Regex SummaryRx();

    [GeneratedRegex(@"rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/")]
    private static partial Regex RttRx();

    [GeneratedRegex(@"From (\S+?)(?::|\s).*Time to live exceeded", RegexOptions.IgnoreCase)]
    private static partial Regex TtlExceededRx();

    [GeneratedRegex(@"^\s*(\d+)\s+(\*|[0-9a-fA-F.:]+)")]
    private static partial Regex HopRx();

    [GeneratedRegex(@"([\d.]+)\s*ms")]
    private static partial Regex RttValueRx();
}
