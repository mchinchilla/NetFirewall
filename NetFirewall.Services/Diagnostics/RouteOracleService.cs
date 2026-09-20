using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.Diagnostics;

public sealed partial class RouteOracleService : IRouteOracleService
{
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(5);

    private readonly IProcessRunner _runner;
    private readonly DiagnosticsOptions _opts;

    public RouteOracleService(IProcessRunner runner, IOptions<DiagnosticsOptions> opts)
    {
        _runner = runner;
        _opts = opts.Value;
    }

    public async Task<RouteGetResult> GetAsync(string targetIp, long fwmark, string? fromIp, string? iif, CancellationToken ct = default)
    {
        var args = new List<string> { "-j", "route", "get", targetIp };
        if (!string.IsNullOrEmpty(fromIp)) { args.Add("from"); args.Add(fromIp); }
        if (!string.IsNullOrEmpty(iif))    { args.Add("iif");  args.Add(iif); }
        if (fwmark > 0)                    { args.Add("mark"); args.Add("0x" + fwmark.ToString("x", CultureInfo.InvariantCulture)); }

        var run = await _runner.RunAsync(_opts.IpPath, args, Budget, ct);
        if (!run.Success)
        {
            var err = FirstLine(run.Error) ?? "ip route get failed";
            return new RouteGetResult(targetIp, null, null, null, null, fwmark > 0 ? $"0x{fwmark:x}" : null, run.Output, Array.Empty<string>(), err);
        }
        return ParseRouteGet(targetIp, fwmark, run.Output);
    }

    public async Task<IReadOnlyList<IpRuleEntry>> ListRulesAsync(CancellationToken ct = default)
    {
        var run = await _runner.RunAsync(_opts.IpPath, new[] { "-j", "rule", "list" }, Budget, ct);
        return run.Success ? ParseRules(run.Output) : Array.Empty<IpRuleEntry>();
    }

    public async Task<IReadOnlyList<IpRouteEntry>> ShowTableAsync(string table, CancellationToken ct = default)
    {
        if (!TableRx().IsMatch(table)) throw new ArgumentException("Invalid table name.", nameof(table));
        var run = await _runner.RunAsync(_opts.IpPath, new[] { "-j", "route", "show", "table", table }, Budget, ct);
        return run.Success ? ParseRoutes(run.Output) : Array.Empty<IpRouteEntry>();
    }

    // ───────────────────────── parsing (pure) ─────────────────────────

    internal static RouteGetResult ParseRouteGet(string target, long fwmark, string output)
    {
        var warnings = new List<string>();
        string? dev = null, gw = null, src = null, table = null, mark = fwmark > 0 ? $"0x{fwmark:x}" : null;

        try
        {
            using var doc = JsonDocument.Parse(output);
            var first = doc.RootElement.ValueKind == JsonValueKind.Array && doc.RootElement.GetArrayLength() > 0
                ? doc.RootElement[0]
                : default;
            if (first.ValueKind == JsonValueKind.Object)
            {
                dev   = Str(first, "dev");
                gw    = Str(first, "gateway");
                src   = Str(first, "prefsrc");
                table = Str(first, "table");
                if (first.TryGetProperty("mark", out var m) && m.ValueKind == JsonValueKind.Number)
                    mark = "0x" + m.GetInt64().ToString("x", CultureInfo.InvariantCulture);
            }
        }
        catch (JsonException)
        {
            // Older iproute2 without -j support prints text; fall back to token scraping.
            dev   = Cap(TextDevRx(), output);
            gw    = Cap(TextViaRx(), output);
            src   = Cap(TextSrcRx(), output);
            table = Cap(TextTableRx(), output);
        }

        if (dev is null) warnings.Add("No route found.");
        else if (dev == "lo") warnings.Add("Target is a local address of this host.");
        if (fwmark > 0 && table is null && dev is not null)
            warnings.Add("Lookup with this mark fell through to the main table — no policy route matched.");

        return new RouteGetResult(target, dev, gw, src, table, mark, output, warnings);
    }

    internal static IReadOnlyList<IpRuleEntry> ParseRules(string output)
    {
        var list = new List<IpRuleEntry>();
        try
        {
            using var doc = JsonDocument.Parse(output);
            foreach (var r in doc.RootElement.EnumerateArray())
            {
                var prio = r.TryGetProperty("priority", out var p) && p.ValueKind == JsonValueKind.Number ? p.GetInt32() : 0;
                long? fw = null;
                var fwText = Str(r, "fwmark");
                if (fwText is not null)
                {
                    var slash = fwText.IndexOf('/');
                    var head = slash > 0 ? fwText[..slash] : fwText;
                    if (head.StartsWith("0x", StringComparison.OrdinalIgnoreCase) &&
                        long.TryParse(head.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var hex)) fw = hex;
                    else if (long.TryParse(head, out var dec)) fw = dec;
                }
                list.Add(new IpRuleEntry(prio, fw, Str(r, "table"), r.GetRawText()));
            }
        }
        catch (JsonException) { /* unparseable → empty */ }
        return list;
    }

    internal static IReadOnlyList<IpRouteEntry> ParseRoutes(string output)
    {
        var list = new List<IpRouteEntry>();
        try
        {
            using var doc = JsonDocument.Parse(output);
            foreach (var r in doc.RootElement.EnumerateArray())
            {
                var metric = r.TryGetProperty("metric", out var m) && m.ValueKind == JsonValueKind.Number ? m.GetInt32() : (int?)null;
                list.Add(new IpRouteEntry(Str(r, "dst") ?? "?", Str(r, "gateway"), Str(r, "dev"), metric, r.GetRawText()));
            }
        }
        catch (JsonException) { /* unparseable → empty */ }
        return list;
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static string? Cap(Regex rx, string s) { var m = rx.Match(s); return m.Success ? m.Groups[1].Value : null; }

    private static string? FirstLine(string? s) =>
        string.IsNullOrWhiteSpace(s) ? null : s.Split('\n', StringSplitOptions.RemoveEmptyEntries)[0].Trim();

    [GeneratedRegex(@"^[A-Za-z0-9_.\-]{1,32}$")] private static partial Regex TableRx();
    [GeneratedRegex(@"\bdev (\S+)")]           private static partial Regex TextDevRx();
    [GeneratedRegex(@"\bvia (\S+)")]           private static partial Regex TextViaRx();
    [GeneratedRegex(@"\bsrc (\S+)")]           private static partial Regex TextSrcRx();
    [GeneratedRegex(@"\btable (\S+)")]         private static partial Regex TextTableRx();
}
