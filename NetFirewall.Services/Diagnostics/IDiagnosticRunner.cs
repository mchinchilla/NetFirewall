using NetFirewall.Models;
using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics;

/// <summary>What a tool body hands back: its result, the verdict status (ok/warn/fail) and a one-line summary.</summary>
public sealed record DiagOutcome<T>(T Result, string Status, string Summary);

/// <summary>
/// The one wrapper every diagnostics endpoint goes through: takes a gate slot,
/// opens a <c>diag_runs</c> row, runs the tool body under a time budget, maps
/// timeouts/exceptions to statuses, closes the row, and returns the envelope the
/// Web renders. History and live results are therefore the same shape.
/// </summary>
public interface IDiagnosticRunner
{
    /// <param name="tool">One of <see cref="DiagTools"/>.</param>
    /// <param name="family">One of <see cref="DiagFamilies"/> (concurrency slot).</param>
    /// <param name="target">Human-readable subject stored in the row (host, interface…).</param>
    /// <param name="requestedBy">Username from the session claims.</param>
    /// <param name="parameters">Request record, already redacted; persisted as JSON.</param>
    /// <param name="budget">Wall-clock budget; the body's token is cancelled at the deadline.</param>
    Task<ServiceResponse<DiagRunEnvelope<T>>> RunAsync<T>(
        string tool,
        string family,
        string? target,
        string? requestedBy,
        object? parameters,
        TimeSpan budget,
        Func<CancellationToken, Task<DiagOutcome<T>>> body,
        CancellationToken ct = default);
}
