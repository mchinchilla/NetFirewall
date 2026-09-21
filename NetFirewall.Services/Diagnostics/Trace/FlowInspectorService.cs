using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Diagnostics.Jobs;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.Diagnostics.Trace;

public sealed partial class FlowInspectorService : IFlowInspectorService
{
    private const string Table = IFlowInspectorService.TraceTableName;
    private static readonly TimeSpan NftTimeout = TimeSpan.FromSeconds(5);

    private readonly IProcessRunner _runner;
    private readonly IDiagnosticJobRegistry _jobs;
    private readonly DiagnosticsOptions _opts;
    private readonly ILogger<FlowInspectorService> _logger;

    public FlowInspectorService(
        IProcessRunner runner,
        IDiagnosticJobRegistry jobs,
        IOptions<DiagnosticsOptions> opts,
        ILogger<FlowInspectorService> logger)
    {
        _runner = runner;
        _jobs = jobs;
        _opts = opts.Value;
        _logger = logger;
    }

    public Guid? Start(TraceRequest request, string? requestedBy)
    {
        var (preMatch, outMatch, spec) = BuildMatchers(request);
        var handle = _jobs.TryStart(DiagJobKind.Trace, spec, requestedBy);
        if (handle is null) return null;

        // Fire and forget: the handle owns the lifetime and always ends the job,
        // even if this task throws. The UI polls the registry.
        _ = Task.Run(() => RunAsync(handle, request, preMatch, outMatch, spec));
        return handle.Id;
    }

    private async Task RunAsync(IDiagnosticJobHandle handle, TraceRequest request, IReadOnlyList<string> preMatch, IReadOnlyList<string> outMatch, string spec)
    {
        using (handle)
        {
            var events = new List<TraceEvent>();
            var installed = false;
            var dropped = 0;
            string? error = null;

            try
            {
                if (!OperatingSystem.IsLinux())
                {
                    handle.Complete(new TraceResult(events, spec, false, 0, "The flow inspector is Linux-only."));
                    return;
                }

                // Always start from a clean slate: a previous daemon crash could have
                // left the table behind (the startup sweeper covers that too).
                await DeleteTableAsync(CancellationToken.None);

                error = await InstallAsync(preMatch, outMatch, handle.Token);
                if (error is not null)
                {
                    // Nothing was traced and nothing will be. Completing here would paint
                    // the panel green over an error the operator has to act on.
                    handle.Fail(error);
                    return;
                }
                installed = true;

                var duration = TimeSpan.FromSeconds(Math.Clamp(request.DurationSec, 5, 60));
                var maxEvents = Math.Clamp(request.MaxEvents, 10, 5000);

                using var budget = CancellationTokenSource.CreateLinkedTokenSource(handle.Token);
                budget.CancelAfter(duration);

                await using var monitor = _runner.Start(_opts.NftPath, ["monitor", "trace"], budget.Token);
                try
                {
                    await foreach (var line in monitor.Output.ReadAllAsync(budget.Token))
                    {
                        if (ParseLine(line) is not { } ev) continue;
                        events.Add(ev);
                        handle.Progress(events.Count, events.Count >= maxEvents);
                        if (events.Count >= maxEvents) break;
                    }
                }
                catch (OperationCanceledException)
                {
                    // Duration elapsed or the operator cancelled — both are normal ends.
                }
                dropped = monitor.DroppedLines;
                await monitor.StopAsync();

                handle.Complete(new TraceResult(events, spec, events.Count >= maxEvents || dropped > 0, dropped));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Flow inspector job {Id} failed", handle.Id);
                handle.Complete(new TraceResult(events, spec, false, dropped, ex.Message));
            }
            finally
            {
                // Non-negotiable: the table goes away even if everything above threw,
                // and with a token that cannot already be cancelled.
                if (installed) await DeleteTableAsync(CancellationToken.None);
            }
        }
    }

    // ───────────────────────── nftables plumbing ─────────────────────────

    private async Task<string?> InstallAsync(IReadOnlyList<string> preMatch, IReadOnlyList<string> outMatch, CancellationToken ct)
    {
        static string[] Rule(string chain, IReadOnlyList<string> match) =>
            new[] { "add", "rule", "ip", Table, chain }.Concat(match).Concat(["meta", "nftrace", "set", "1"]).ToArray();

        // Priority -300 is the `raw` hook: we mark the packet before conntrack and
        // before any of the operator's tables, so the trace shows its whole journey.
        var steps = new List<string[]>();
        steps.Add(new[] { "add", "table", "ip", Table });
        steps.Add(new[] { "add", "chain", "ip", Table, "pre", "{ type filter hook prerouting priority -300; policy accept; }" });
        steps.Add(new[] { "add", "chain", "ip", Table, "out", "{ type filter hook output priority -300; policy accept; }" });
        steps.Add(Rule("pre", preMatch));
        steps.Add(Rule("out", outMatch));

        foreach (var args in steps)
        {
            var res = await _runner.RunAsync(_opts.NftPath, args, NftTimeout, ct);
            if (!res.Success)
            {
                await DeleteTableAsync(CancellationToken.None);
                return $"nft {string.Join(' ', args)} failed: {res.Error.Trim()}";
            }
        }
        return null;
    }

    private async Task DeleteTableAsync(CancellationToken ct)
    {
        try
        {
            // Absent table → non-zero exit; that is the desired end state either way.
            await _runner.RunAsync(_opts.NftPath, ["delete", "table", "ip", Table], NftTimeout, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not delete the temporary trace table '{Table}' — run: nft delete table ip {Table}", Table, Table);
        }
    }

    /// <summary>
    /// Build the nft matchers. Inputs are pre-validated literals; they are still
    /// passed as separate argv elements, never concatenated into a command string.
    /// The output chain gets no <c>iifname</c> — locally generated packets have no
    /// ingress interface and nft would reject the rule.
    /// </summary>
    internal static (IReadOnlyList<string> Pre, IReadOnlyList<string> Out, string Spec) BuildMatchers(TraceRequest r)
    {
        var common = new List<string>();
        if (!string.IsNullOrWhiteSpace(r.Src)) { common.Add("ip"); common.Add("saddr"); common.Add(r.Src); }
        if (!string.IsNullOrWhiteSpace(r.Dst)) { common.Add("ip"); common.Add("daddr"); common.Add(r.Dst); }
        if (!string.IsNullOrWhiteSpace(r.Protocol))
        {
            common.Add("ip"); common.Add("protocol"); common.Add(r.Protocol);
            if (r.Port is > 0 && r.Protocol is "tcp" or "udp")
            {
                // Match either direction: you rarely know which way the interesting packet flows.
                common.Add(r.Protocol); common.Add("dport"); common.Add(r.Port.Value.ToString(CultureInfo.InvariantCulture));
            }
        }

        var pre = new List<string>();
        if (!string.IsNullOrWhiteSpace(r.Interface)) { pre.Add("iifname"); pre.Add(r.Interface); }
        pre.AddRange(common);

        var spec = string.Join(' ', pre.Count > 0 ? pre : ["(everything)"]);
        return (pre, common, spec);
    }

    // ───────────────────────── parsing (pure) ─────────────────────────

    /// <summary>
    /// <c>trace id 4e0e1e5b ip filter input rule ip saddr 1.2.3.4 tcp dport 22 accept (verdict accept)</c>
    /// → one event. Lines that are not trace output (nft prints nothing else here) return null.
    /// </summary>
    internal static TraceEvent? ParseLine(string line)
    {
        var m = TraceRx().Match(line ?? string.Empty);
        return m.Success
            ? new TraceEvent(m.Groups["id"].Value, m.Groups["family"].Value, m.Groups["table"].Value,
                m.Groups["chain"].Value, m.Groups["kind"].Value, m.Groups["detail"].Value.Trim(), line!.Trim())
            : null;
    }

    [GeneratedRegex(@"^trace id (?<id>\S+) (?<family>\S+) (?<table>\S+) (?<chain>\S+) (?<kind>packet|rule|verdict|policy)\b(?<detail>.*)$")]
    private static partial Regex TraceRx();
}
