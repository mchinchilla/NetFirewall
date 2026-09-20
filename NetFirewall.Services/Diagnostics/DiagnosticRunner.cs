using System.Diagnostics;
using Microsoft.Extensions.Logging;
using NetFirewall.Models;
using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics;

public sealed class DiagnosticRunner : IDiagnosticRunner
{
    private readonly IDiagnosticRunStore _store;
    private readonly IDiagnosticGate _gate;
    private readonly ILogger<DiagnosticRunner> _logger;

    public DiagnosticRunner(IDiagnosticRunStore store, IDiagnosticGate gate, ILogger<DiagnosticRunner> logger)
    {
        _store = store;
        _gate = gate;
        _logger = logger;
    }

    public async Task<ServiceResponse<DiagRunEnvelope<T>>> RunAsync<T>(
        string tool,
        string family,
        string? target,
        string? requestedBy,
        object? parameters,
        TimeSpan budget,
        Func<CancellationToken, Task<DiagOutcome<T>>> body,
        CancellationToken ct = default)
    {
        var startedAt = DateTime.UtcNow;

        using var lease = _gate.TryEnter(family);
        if (lease is null)
        {
            // Refused, not queued — and not persisted, so history stays a log of
            // things that actually ran. The endpoint audits this as diag.denied.
            return new ServiceResponse<DiagRunEnvelope<T>>
            {
                Success = false,
                Message = $"Another {tool} run is already in progress — try again in a moment.",
                Data = new DiagRunEnvelope<T>(Guid.Empty, startedAt, 0, DiagRunStatus.Busy, default),
            };
        }

        // History is a feature, not a dependency: a DB hiccup must not stop a ping.
        var persisted = true;
        Guid runId;
        try
        {
            runId = await _store.StartAsync(tool, target, requestedBy, parameters, ct);
        }
        catch (Exception ex)
        {
            persisted = false;
            runId = Guid.NewGuid();
            _logger.LogWarning(ex, "diag_runs insert failed — running {Tool} without history", tool);
        }

        var sw = Stopwatch.StartNew();
        string status;
        string summary;
        T? result = default;

        using var budgetCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budgetCts.CancelAfter(budget);
        try
        {
            var outcome = await body(budgetCts.Token);
            result  = outcome.Result;
            status  = outcome.Status;
            summary = outcome.Summary;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            status  = DiagRunStatus.Timeout;
            summary = $"Timed out after {budget.TotalSeconds:0} s.";
        }
        catch (OperationCanceledException)
        {
            status  = DiagRunStatus.Error;
            summary = "Cancelled by the caller.";
        }
        catch (Exception ex)
        {
            status  = DiagRunStatus.Error;
            summary = ex.Message;
            _logger.LogError(ex, "Diagnostics tool {Tool} failed", tool);
        }
        sw.Stop();

        if (persisted)
        {
            // Close the row even if the caller went away (bounded by the DB command timeout).
            try { await _store.FinishAsync(runId, status, result, summary, CancellationToken.None); }
            catch (Exception ex) { _logger.LogWarning(ex, "diag_runs update failed for run {Id}", runId); }
        }

        var envelope = new DiagRunEnvelope<T>(runId, startedAt, (int)sw.ElapsedMilliseconds, status, result);

        // ok/warn/fail = the tool ran and that is its verdict → Success. The rest
        // = it did not complete → failure envelope, still carrying what we have.
        return DiagRunStatus.IsVerdict(status)
            ? ServiceResponse<DiagRunEnvelope<T>>.Ok(envelope, summary)
            : new ServiceResponse<DiagRunEnvelope<T>> { Success = false, Message = summary, Data = envelope };
    }
}
