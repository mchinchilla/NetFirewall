using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.Diagnostics;

public sealed partial class ConntrackLookupService : IConntrackLookupService
{
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(8);
    private static readonly HashSet<string> TcpStates = new(StringComparer.Ordinal)
        { "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE", "LISTEN" };

    private readonly IProcessRunner _runner;
    private readonly DiagnosticsOptions _opts;

    public ConntrackLookupService(IProcessRunner runner, IOptions<DiagnosticsOptions> opts)
    {
        _runner = runner;
        _opts = opts.Value;
    }

    public async Task<ConntrackLookupResult> LookupAsync(string? src, string? dst, string proto, int port, int limit, CancellationToken ct = default)
    {
        var args = new List<string> { "-L", "-o", "extended" };
        AddAddressFilter(args, "-s", "--mask-src", src);
        AddAddressFilter(args, "-d", "--mask-dst", dst);
        if (!string.IsNullOrEmpty(proto))
        {
            args.Add("-p"); args.Add(proto);
            if (port > 0 && proto is "tcp" or "udp") { args.Add("--dport"); args.Add(port.ToString(CultureInfo.InvariantCulture)); }
        }

        var run = await _runner.RunAsync(_opts.ConntrackPath, args, Budget, ct);
        if (run.ExitCode == -1)
            return new ConntrackLookupResult(Array.Empty<ConntrackFlow>(), 0, false, FirstLine(run.Error) ?? "conntrack failed");
        // conntrack exits 0 with "N flow entries have been shown" on stderr; non-zero = real error.
        if (!run.Success && string.IsNullOrWhiteSpace(run.Output))
            return new ConntrackLookupResult(Array.Empty<ConntrackFlow>(), 0, false, FirstLine(run.Error) ?? $"conntrack exit {run.ExitCode}");

        return Parse(run.Output, limit);
    }

    // ───────────────────────── parsing (pure) ─────────────────────────

    internal static ConntrackLookupResult Parse(string output, int limit)
    {
        var flows = new List<ConntrackFlow>();
        var total = 0;
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var flow = ParseLine(line);
            if (flow is null) continue;
            total++;
            if (flows.Count < limit) flows.Add(flow);
        }
        return new ConntrackLookupResult(flows, total, total > flows.Count);
    }

    /// <summary>
    /// <c>-o extended</c> line: <c>ipv4 2 tcp 6 431999 ESTABLISHED src=A dst=B sport=1 dport=2 packets= bytes= src=B' dst=A' sport= dport= packets= bytes= [ASSURED] mark=0 use=1</c>.
    /// First src/dst pair = original direction, second = reply direction (post-NAT).
    /// </summary>
    internal static ConntrackFlow? ParseLine(string line)
    {
        var head = HeadRx().Match(line);
        if (!head.Success) return null;
        var proto = head.Groups[1].Value;

        var srcs = SrcRx().Matches(line);
        var dsts = DstRx().Matches(line);
        if (srcs.Count == 0 || dsts.Count == 0) return null;

        var sports = SportRx().Matches(line);
        var dports = DportRx().Matches(line);
        var bytes  = BytesRx().Matches(line);

        string? state = null;
        foreach (var token in line.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            if (TcpStates.Contains(token)) { state = token; break; }
        }
        state ??= line.Contains("[UNREPLIED]", StringComparison.Ordinal) ? "UNREPLIED" : null;

        var markM = MarkRx().Match(line);
        string? mark = markM.Success && long.TryParse(markM.Groups[1].Value, out var mk) && mk != 0
            ? "0x" + mk.ToString("x", CultureInfo.InvariantCulture)
            : null;

        return new ConntrackFlow(
            proto,
            srcs[0].Groups[1].Value,
            dsts[0].Groups[1].Value,
            sports.Count > 0 ? int.Parse(sports[0].Groups[1].Value, CultureInfo.InvariantCulture) : null,
            dports.Count > 0 ? int.Parse(dports[0].Groups[1].Value, CultureInfo.InvariantCulture) : null,
            state,
            mark,
            bytes.Count > 0 ? long.Parse(bytes[0].Groups[1].Value, CultureInfo.InvariantCulture) : null,
            bytes.Count > 1 ? long.Parse(bytes[1].Groups[1].Value, CultureInfo.InvariantCulture) : null,
            srcs.Count > 1 ? srcs[1].Groups[1].Value : null,
            dsts.Count > 1 ? dsts[1].Groups[1].Value : null,
            line.Trim());
    }

    /// <summary>conntrack takes <c>-s IP</c> plus a separate <c>--mask-src</c>; expand IPv4 CIDRs, pass IPv6/hosts as-is.</summary>
    private static void AddAddressFilter(List<string> args, string flag, string maskFlag, string? value)
    {
        if (string.IsNullOrEmpty(value)) return;
        var slash = value.IndexOf('/');
        if (slash < 0) { args.Add(flag); args.Add(value); return; }

        var ip = value[..slash];
        args.Add(flag); args.Add(ip);
        if (IPAddress.TryParse(ip, out var parsed) && parsed.AddressFamily == AddressFamily.InterNetwork
            && int.TryParse(value[(slash + 1)..], out var prefix) && prefix is >= 0 and <= 32)
        {
            var maskBits = prefix == 0 ? 0u : uint.MaxValue << (32 - prefix);
            var mask = new IPAddress(BitConverter.GetBytes(maskBits).Reverse().ToArray());
            args.Add(maskFlag); args.Add(mask.ToString());
        }
    }

    private static string? FirstLine(string? s) =>
        string.IsNullOrWhiteSpace(s) ? null : s.Split('\n', StringSplitOptions.RemoveEmptyEntries)[0].Trim();

    [GeneratedRegex(@"^\S+\s+\d+\s+(\w+)\s+\d+")] private static partial Regex HeadRx();
    [GeneratedRegex(@"\bsrc=(\S+)")]              private static partial Regex SrcRx();
    [GeneratedRegex(@"\bdst=(\S+)")]              private static partial Regex DstRx();
    [GeneratedRegex(@"\bsport=(\d+)")]            private static partial Regex SportRx();
    [GeneratedRegex(@"\bdport=(\d+)")]            private static partial Regex DportRx();
    [GeneratedRegex(@"\bbytes=(\d+)")]            private static partial Regex BytesRx();
    [GeneratedRegex(@"\bmark=(\d+)")]             private static partial Regex MarkRx();
}
