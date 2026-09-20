using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.Diagnostics;

public sealed partial class DropLogService : IDropLogService
{
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(10);
    private const int TopN = 10;

    private readonly IProcessRunner _runner;
    private readonly DiagnosticsOptions _opts;

    public DropLogService(IProcessRunner runner, IOptions<DiagnosticsOptions> opts)
    {
        _runner = runner;
        _opts = opts.Value;
    }

    public async Task<DropLogResult> QueryAsync(string? iface, int sinceMinutes, int lines, string filter, CancellationToken ct = default)
    {
        lines = Math.Clamp(lines, 1, _opts.MaxJournalLines);
        var args = new[]
        {
            "-k", "-q", "--no-pager", "-o", "short-iso",
            "--since", "-" + sinceMinutes.ToString(CultureInfo.InvariantCulture) + "min",
            "-n", lines.ToString(CultureInfo.InvariantCulture),
        };

        var run = await _runner.RunAsync(_opts.JournalctlPath, args, Budget, ct);
        if (run.ExitCode == -1 || (!run.Success && string.IsNullOrWhiteSpace(run.Output)))
            return new DropLogResult(Array.Empty<DropLogEntry>(), 0, false,
                Array.Empty<DropLogTop>(), Array.Empty<DropLogTop>(), Array.Empty<DropLogTop>(),
                FirstLine(run.Error) ?? "journalctl failed");

        return Parse(run.Output, iface, filter, lines);
    }

    // ───────────────────────── parsing (pure) ─────────────────────────

    internal static DropLogResult Parse(string output, string? iface, string filter, int requestedLines)
    {
        var entries = new List<DropLogEntry>();
        var scanned = 0;
        foreach (var raw in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            scanned++;
            var entry = ParseLine(raw);
            if (entry is null) continue;

            var keep = filter switch
            {
                "martians" => entry.Prefix == "martian",
                "wg"       => entry.Prefix == "wg",
                "all"      => true,
                _          => entry.Prefix is not ("martian" or "wg" or "kernel"), // drops = nflog lines
            };
            if (!keep) continue;
            if (!string.IsNullOrEmpty(iface) && entry.In != iface && entry.Out != iface) continue;
            entries.Add(entry);
        }

        return new DropLogResult(
            entries,
            scanned,
            Truncated: scanned >= requestedLines,
            TopPrefixes: Top(entries.Select(e => e.Prefix)),
            TopSources:  Top(entries.Where(e => e.Src is not null).Select(e => e.Src!)),
            TopPorts:    Top(entries.Where(e => e.Dpt is not null).Select(e => $"{e.Proto?.ToLowerInvariant()}/{e.Dpt}")));
    }

    /// <summary>
    /// <c>2026-09-18T21:11:51-0600 host kernel: INPUT_DROP: IN=ens192 OUT= … SRC=… DST=… PROTO=TCP SPT=… DPT=… MARK=0x500</c>.
    /// Colour/level artifacts before the prefix (<c>\e[5;185m</c>, <c>5:185m</c>) are stripped.
    /// Non-nflog lines come back with Prefix "martian" / "wg" / "kernel" so callers can filter.
    /// </summary>
    internal static DropLogEntry? ParseLine(string raw)
    {
        var m = JournalLineRx().Match(raw);
        if (!m.Success) return null;

        DateTime? at = DateTimeOffset.TryParse(m.Groups[1].Value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var ts)
            ? ts.UtcDateTime : null;
        var msg = ArtifactRx().Replace(m.Groups[2].Value, string.Empty).Trim();

        var nf = NfLogRx().Match(msg);
        if (nf.Success)
        {
            return new DropLogEntry(
                at,
                nf.Groups["prefix"].Value,
                Empty(nf.Groups["in"].Value),
                Empty(nf.Groups["out"].Value),
                nf.Groups["src"].Success ? nf.Groups["src"].Value : null,
                nf.Groups["dst"].Success ? nf.Groups["dst"].Value : null,
                nf.Groups["proto"].Success ? nf.Groups["proto"].Value : null,
                nf.Groups["spt"].Success ? int.Parse(nf.Groups["spt"].Value, CultureInfo.InvariantCulture) : null,
                nf.Groups["dpt"].Success ? int.Parse(nf.Groups["dpt"].Value, CultureInfo.InvariantCulture) : null,
                nf.Groups["mark"].Success ? nf.Groups["mark"].Value : null,
                msg);
        }

        if (msg.Contains("martian", StringComparison.OrdinalIgnoreCase))
        {
            var src = MartianSrcRx().Match(msg);
            var dev = MartianDevRx().Match(msg);
            return new DropLogEntry(at, "martian", dev.Success ? dev.Groups[1].Value : null, null,
                src.Success ? src.Groups[1].Value : null, null, null, null, null, null, msg);
        }
        if (msg.Contains("wireguard", StringComparison.OrdinalIgnoreCase) || WgIfaceRx().IsMatch(msg))
            return new DropLogEntry(at, "wg", null, null, null, null, null, null, null, null, msg);

        return new DropLogEntry(at, "kernel", null, null, null, null, null, null, null, null, msg);
    }

    private static IReadOnlyList<DropLogTop> Top(IEnumerable<string> keys) =>
        keys.GroupBy(k => k, StringComparer.Ordinal)
            .Select(g => new DropLogTop(g.Key, g.Count()))
            .OrderByDescending(t => t.Count).ThenBy(t => t.Key, StringComparer.Ordinal)
            .Take(TopN)
            .ToList();

    private static string? Empty(string s) => string.IsNullOrEmpty(s) ? null : s;

    private static string? FirstLine(string? s) =>
        string.IsNullOrWhiteSpace(s) ? null : s.Split('\n', StringSplitOptions.RemoveEmptyEntries)[0].Trim();

    // "<iso-timestamp> <host> kernel: <message>"
    [GeneratedRegex(@"^(\S+)\s+\S+\s+kernel:\s?(.*)$")]
    private static partial Regex JournalLineRx();

    // ANSI colour codes and the "5:185m" residue journald leaves from KERN_* prefixes.
    [GeneratedRegex(@"\x1b\[[0-9;]*m|^(?:\d+:\d+m)+")]
    private static partial Regex ArtifactRx();

    [GeneratedRegex(@"(?<prefix>[A-Za-z0-9_\-]+):\s+IN=(?<in>\S*)\s+OUT=(?<out>\S*)(?:.*?\bSRC=(?<src>\S+))?(?:.*?\bDST=(?<dst>\S+))?(?:.*?\bPROTO=(?<proto>\S+))?(?:.*?\bSPT=(?<spt>\d+))?(?:.*?\bDPT=(?<dpt>\d+))?(?:.*?\bMARK=(?<mark>0x[0-9a-fA-F]+))?")]
    private static partial Regex NfLogRx();

    [GeneratedRegex(@"martian source \S+ from ([^\s,]+)", RegexOptions.IgnoreCase)]
    private static partial Regex MartianSrcRx();

    [GeneratedRegex(@"on dev (\S+)", RegexOptions.IgnoreCase)]
    private static partial Regex MartianDevRx();

    [GeneratedRegex(@"\bwg\d+\b")]
    private static partial Regex WgIfaceRx();
}
