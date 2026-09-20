using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics.Doctors;

public sealed class DoctorRunner : IDoctorRunner
{
    private readonly DiagnosticsOptions _opts;
    private readonly ILogger<DoctorRunner> _logger;

    public DoctorRunner(IOptions<DiagnosticsOptions> opts, ILogger<DoctorRunner> logger)
    {
        _opts = opts.Value;
        _logger = logger;
    }

    public async Task<DiagReport> RunAsync<TContext>(
        string tool,
        string subject,
        TContext context,
        IEnumerable<IDoctorCheck<TContext>> checks,
        CancellationToken ct = default)
    {
        var started = DateTime.UtcNow;
        var sw = Stopwatch.StartNew();
        var list = checks.ToList();
        var results = new IReadOnlyList<DiagCheck>[list.Count];

        // Bounded fan-out: the daemon unit runs with TasksMax=128 and every check
        // may spawn a process. The gate keeps a 25-check doctor to a handful of
        // concurrent children while still finishing inside the budget.
        using var gate = new SemaphoreSlim(Math.Max(1, _opts.DoctorParallelism));
        var perCheck = TimeSpan.FromSeconds(Math.Max(1, _opts.CheckTimeoutSeconds));

        await Task.WhenAll(list.Select(async (check, i) =>
        {
            await gate.WaitAsync(ct);
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(perCheck);
                var timer = Stopwatch.StartNew();
                try
                {
                    results[i] = await check.RunAsync(context, cts.Token);
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested)
                {
                    // A slow check must not cost the whole report.
                    results[i] = [DiagCheck.Skip(check.Id, check.Category, check.Id, $"Timed out after {perCheck.TotalSeconds:0} s.")];
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "{Tool} check {Id} threw", tool, check.Id);
                    results[i] = [DiagCheck.Skip(check.Id, check.Category, check.Id, $"Check could not run: {ex.Message}")];
                }
                results[i] = results[i].Select(r => r with { DurationMs = (int)timer.ElapsedMilliseconds }).ToList();
            }
            finally
            {
                gate.Release();
            }
        }));

        return new DiagReport(tool, subject, started, (int)sw.ElapsedMilliseconds, results.SelectMany(r => r).ToList());
    }
}
