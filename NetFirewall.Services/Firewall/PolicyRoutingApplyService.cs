using System.Globalization;
using System.Runtime.Versioning;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Firewall;
using Npgsql;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.Firewall;

/// <summary>
/// Daemon-side reconciler. Three phases run in order; each phase contributes
/// to the returned <see cref="PolicyRoutingApplyResult"/> regardless of dry-run.
///
/// Phase 1 — <c>/etc/iproute2/rt_tables</c>: ensure every enabled
/// <c>fw_route_tables</c> row has a line in the file. Idempotent — we keep
/// every existing line not managed by us. We tag managed lines with a
/// trailing <c># netfirewall</c> comment.
///
/// Phase 2 — <c>ip rule</c>: enumerate current rules, classify each as
/// "managed" (matches a fwmark we know about) or "external". Add missing
/// managed rules; delete managed rules that no longer have a DB entry.
/// External rules are never touched.
///
/// Phase 3 — <c>ip route</c>: for every <c>fw_static_routes</c> row whose
/// <c>table_id</c> resolves to a known table, <c>ip route replace</c> in that
/// table. We don't garbage-collect routes — operators may add ad-hoc routes
/// out-of-band and we shouldn't break them.
/// </summary>
[SupportedOSPlatform("linux")]
public sealed partial class PolicyRoutingApplyService : IPolicyRoutingApplyService
{
    private const string RtTablesPath = "/etc/iproute2/rt_tables";
    private const string NetFirewallTag = "# netfirewall";

    private readonly NpgsqlDataSource _ds;
    private readonly IProcessRunner _runner;
    private readonly ILogger<PolicyRoutingApplyService> _logger;

    public PolicyRoutingApplyService(
        NpgsqlDataSource ds,
        IProcessRunner runner,
        ILogger<PolicyRoutingApplyService> logger)
    {
        _ds = ds;
        _runner = runner;
        _logger = logger;
    }

    public async Task<PolicyRoutingApplyResult> ApplyAsync(bool dryRun, CancellationToken ct = default)
    {
        var steps = new List<RoutingStep>();

        try
        {
            await using var conn = await _ds.OpenConnectionAsync(ct);
            var tables = await LoadEnabledTablesAsync(conn, ct);
            var rules = await LoadEnabledRulesAsync(conn, ct);
            var routes = await LoadTaggedRoutesAsync(conn, ct);

            await ReconcileRtTablesAsync(tables, dryRun, steps, ct);
            await ReconcileIpRulesAsync(rules, dryRun, steps, ct);
            await ReconcileRoutesAsync(routes, dryRun, steps, ct);

            var failures = steps.Count(s => s.Executed && !s.Success);
            return new PolicyRoutingApplyResult(
                Success: failures == 0,
                DryRun: dryRun,
                Steps: steps,
                Error: failures == 0 ? null : $"{failures} command(s) failed");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Policy routing apply blew up before completion");
            return new PolicyRoutingApplyResult(false, dryRun, steps, ex.Message);
        }
    }

    // ─────────────────────────── DB loaders ───────────────────────────

    private sealed record TableRow(int TableId, string Name);
    private sealed record RuleRow(long Fwmark, string TableName, int? Priority);
    private sealed record RouteRow(string Destination, string? Gateway, int Metric, string TableName);

    private static async Task<List<TableRow>> LoadEnabledTablesAsync(NpgsqlConnection conn, CancellationToken ct)
    {
        var list = new List<TableRow>();
        await using var cmd = new NpgsqlCommand(
            "SELECT table_id, table_name FROM fw_route_tables WHERE enabled = true ORDER BY table_id", conn);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(new TableRow(r.GetInt32(0), r.GetString(1)));
        return list;
    }

    private static async Task<List<RuleRow>> LoadEnabledRulesAsync(NpgsqlConnection conn, CancellationToken ct)
    {
        var list = new List<RuleRow>();
        await using var cmd = new NpgsqlCommand(
            "SELECT fwmark, table_name, priority FROM fw_policy_rules WHERE enabled = true ORDER BY priority NULLS LAST, fwmark", conn);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(new RuleRow(
                r.GetInt64(0),
                r.GetString(1),
                r.IsDBNull(2) ? null : r.GetInt32(2)));
        return list;
    }

    private static async Task<List<RouteRow>> LoadTaggedRoutesAsync(NpgsqlConnection conn, CancellationToken ct)
    {
        var list = new List<RouteRow>();
        await using var cmd = new NpgsqlCommand(@"
            -- host() strips the /32 suffix Postgres adds when casting inet→text,
            -- which `ip route via X/32` would otherwise reject.
            SELECT sr.destination::text,
                   CASE WHEN sr.gateway IS NULL THEN NULL ELSE host(sr.gateway) END,
                   sr.metric,
                   rt.table_name
            FROM fw_static_routes sr
            JOIN fw_route_tables  rt ON rt.id = sr.table_id
            WHERE sr.enabled = true AND rt.enabled = true
            ORDER BY rt.table_name, sr.metric", conn);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
            list.Add(new RouteRow(
                r.GetString(0),
                r.IsDBNull(1) ? null : r.GetString(1),
                r.GetInt32(2),
                r.GetString(3)));
        return list;
    }

    // ─────────────────────────── Phase 1: rt_tables ───────────────────────────

    private async Task ReconcileRtTablesAsync(List<TableRow> tables, bool dryRun, List<RoutingStep> steps, CancellationToken ct)
    {
        // Read whatever's there today. File might not exist on minimal distros — that's fine.
        var existing = File.Exists(RtTablesPath)
            ? await File.ReadAllLinesAsync(RtTablesPath, ct)
            : Array.Empty<string>();

        // Map table_id (text) → managed-by-us flag, so we can update without nuking system entries.
        var managed = new HashSet<int>();
        foreach (var line in existing)
        {
            if (line.Contains(NetFirewallTag) && TryParseRtTablesLine(line, out var tid, out _))
                managed.Add(tid);
        }

        // Build the new file by keeping unmanaged lines verbatim and re-emitting ours.
        var rebuilt = new StringBuilder();
        foreach (var line in existing)
        {
            // Skip our previous managed lines — we'll re-emit them below.
            if (line.Contains(NetFirewallTag)) continue;
            rebuilt.AppendLine(line);
        }
        foreach (var t in tables)
            rebuilt.AppendLine($"{t.TableId}\t{t.Name}\t{NetFirewallTag}");

        var newContent = rebuilt.ToString();
        var current = string.Join('\n', existing) + (existing.Length > 0 ? "\n" : "");

        if (newContent == current)
        {
            steps.Add(new RoutingStep("rt_tables", $"# {RtTablesPath} already in sync ({tables.Count} managed)", true, true, null));
            return;
        }

        var cmdDesc = $"write {RtTablesPath} ({tables.Count} managed entries)";
        if (dryRun)
        {
            steps.Add(new RoutingStep("rt_tables", cmdDesc, false, false, "dry-run"));
            return;
        }

        try
        {
            await File.WriteAllTextAsync(RtTablesPath, newContent, ct);
            steps.Add(new RoutingStep("rt_tables", cmdDesc, true, true, null));
        }
        catch (Exception ex)
        {
            steps.Add(new RoutingStep("rt_tables", cmdDesc, true, false, ex.Message));
        }
    }

    private static bool TryParseRtTablesLine(string line, out int tid, out string name)
    {
        tid = 0; name = "";
        var stripped = line;
        var hash = stripped.IndexOf('#');
        if (hash >= 0) stripped = stripped[..hash];
        var trimmed = stripped.Trim();
        if (trimmed.Length == 0) return false;
        var parts = trimmed.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2) return false;
        if (!int.TryParse(parts[0], out tid)) return false;
        name = parts[1];
        return true;
    }

    // ─────────────────────────── Phase 2: ip rule ───────────────────────────

    private async Task ReconcileIpRulesAsync(List<RuleRow> wanted, bool dryRun, List<RoutingStep> steps, CancellationToken ct)
    {
        // List current rules in machine-friendly form.
        var listResult = await _runner.RunAsync("ip", "-o rule list", TimeSpan.FromSeconds(5), ct);
        if (!listResult.Success)
        {
            steps.Add(new RoutingStep("ip-rule-list", "ip -o rule list", true, false, listResult.Error));
            return;
        }
        var existing = ParseIpRuleList(listResult.Output);

        // "Managed by us" = any current rule whose fwmark matches a fwmark we
        // care about. This way, if the operator re-uses a fwmark in DB with
        // a different table, the old rule gets removed too.
        var wantedFwmarks = wanted.Select(w => w.Fwmark).ToHashSet();
        var toDelete = existing.Where(e => e.Fwmark is { } fm && wantedFwmarks.Contains(fm))
                               .Where(e => !wanted.Any(w => RuleMatches(w, e)))
                               .ToList();

        var toAdd = wanted.Where(w => !existing.Any(e => RuleMatches(w, e)))
                          .ToList();

        // Apply deletions first, then additions. Order inside each list doesn't
        // matter — `ip rule` accepts duplicate priorities, kernel resolves on match.
        foreach (var del in toDelete)
        {
            var cmd = $"ip rule del {del.OriginalArgs}";
            if (dryRun) { steps.Add(new RoutingStep("ip-rule-del", cmd, false, false, "dry-run")); continue; }
            var run = await _runner.RunAsync("ip", $"rule del {del.OriginalArgs}", TimeSpan.FromSeconds(5), ct);
            steps.Add(new RoutingStep("ip-rule-del", cmd, true, run.Success, run.Success ? null : run.Error));
        }

        foreach (var add in toAdd)
        {
            var args = BuildIpRuleAddArgs(add);
            var cmd = $"ip rule add {args}";
            if (dryRun) { steps.Add(new RoutingStep("ip-rule-add", cmd, false, false, "dry-run")); continue; }
            var run = await _runner.RunAsync("ip", $"rule add {args}", TimeSpan.FromSeconds(5), ct);
            steps.Add(new RoutingStep("ip-rule-add", cmd, true, run.Success, run.Success ? null : run.Error));
        }

        if (toAdd.Count == 0 && toDelete.Count == 0)
            steps.Add(new RoutingStep("ip-rule-noop", $"# ip rules already in sync ({wanted.Count} managed)", true, true, null));
    }

    private sealed record ExistingRule(int Priority, long? Fwmark, string TableName, string OriginalArgs);

    /// <summary>
    /// Parse `ip -o rule list` line. Sample:
    ///   "32750:\tfrom all fwmark 0x100 lookup wan1\n"
    /// We extract priority, fwmark, table name, and a normalized "args" string
    /// usable in `ip rule del &lt;args&gt;`.
    /// </summary>
    private static List<ExistingRule> ParseIpRuleList(string output)
    {
        var list = new List<ExistingRule>();
        foreach (var raw in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var line = raw.Trim();
            // Strip "PRIO:\t" prefix.
            var colon = line.IndexOf(':');
            if (colon <= 0 || !int.TryParse(line[..colon], out var prio)) continue;
            var body = line[(colon + 1)..].Trim();

            // fwmark (hex or decimal). Without it we don't manage the rule.
            long? fwmark = null;
            var m = FwmarkRx().Match(body);
            if (m.Success)
            {
                var s = m.Groups[1].Value;
                fwmark = s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                    ? Convert.ToInt64(s, 16)
                    : long.Parse(s, CultureInfo.InvariantCulture);
            }

            // lookup TABLE
            var lookup = LookupRx().Match(body);
            var table = lookup.Success ? lookup.Groups[1].Value : "";

            list.Add(new ExistingRule(prio, fwmark, table, body));
        }
        return list;
    }

    private static bool RuleMatches(RuleRow w, ExistingRule e)
    {
        if (e.Fwmark != w.Fwmark) return false;
        if (!string.Equals(e.TableName, w.TableName, StringComparison.OrdinalIgnoreCase)) return false;
        if (w.Priority is { } p && e.Priority != p) return false;
        return true;
    }

    private static string BuildIpRuleAddArgs(RuleRow r)
    {
        var sb = new StringBuilder();
        sb.Append("fwmark ").Append(r.Fwmark);
        sb.Append(" lookup ").Append(r.TableName);
        if (r.Priority is { } p) sb.Append(" priority ").Append(p);
        return sb.ToString();
    }

    [GeneratedRegex(@"fwmark\s+(0x[0-9a-fA-F]+|\d+)")]
    private static partial Regex FwmarkRx();

    [GeneratedRegex(@"lookup\s+(\S+)")]
    private static partial Regex LookupRx();

    // ─────────────────────────── Phase 3: ip route ───────────────────────────

    private async Task ReconcileRoutesAsync(List<RouteRow> wanted, bool dryRun, List<RoutingStep> steps, CancellationToken ct)
    {
        if (wanted.Count == 0)
        {
            steps.Add(new RoutingStep("ip-route-noop", "# no per-table routes in DB", true, true, null));
            return;
        }

        foreach (var route in wanted)
        {
            // Build the `ip route replace` args. `replace` is idempotent: adds if
            // missing, overwrites if present.
            var args = BuildRouteArgs(route);
            var cmd = $"ip route replace {args} table {route.TableName}";
            if (dryRun) { steps.Add(new RoutingStep("ip-route", cmd, false, false, "dry-run")); continue; }

            var run = await _runner.RunAsync("ip", $"route replace {args} table {route.TableName}", TimeSpan.FromSeconds(5), ct);
            steps.Add(new RoutingStep("ip-route", cmd, true, run.Success, run.Success ? null : run.Error));
        }
    }

    private static string BuildRouteArgs(RouteRow r)
    {
        // destination is either a CIDR ("10.0.0.0/8") or the literal "0.0.0.0/0"
        // which `ip route` accepts as "default". Normalize to make commands
        // readable and shorter.
        var dest = r.Destination == "0.0.0.0/0" ? "default" : r.Destination;
        var sb = new StringBuilder(dest);
        if (!string.IsNullOrEmpty(r.Gateway))
        {
            // Postgres serializes `inet` with a /32 suffix even for single hosts.
            // `ip route … via X/32` is rejected — strip the suffix here.
            var gw = r.Gateway;
            var slash = gw.IndexOf('/');
            if (slash > 0) gw = gw[..slash];
            sb.Append(" via ").Append(gw);
        }
        if (r.Metric > 0)
            sb.Append(" metric ").Append(r.Metric);
        return sb.ToString();
    }
}
