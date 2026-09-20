using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics.Jobs;

/// <summary>
/// In-memory registry for the invasive diagnostics jobs (flow inspector, packet
/// capture). Singleton, modelled on <c>ITerminalSessionRegistry</c>: at most ONE
/// invasive job runs at a time on the whole box — each one inserts kernel state or
/// opens a capture socket, and two operators racing would trip over each other's
/// nftables table.
///
/// Finished jobs stay for a short while so the UI can fetch the result, then age
/// out; the capture files they produced have their own retention.
/// </summary>
public interface IDiagnosticJobRegistry
{
    /// <summary>
    /// Reserve the single invasive slot. Returns null when one is already running
    /// (the caller answers 409). The returned handle owns the job's lifetime:
    /// disposing it releases the slot and marks the job finished.
    /// </summary>
    IDiagnosticJobHandle? TryStart(DiagJobKind kind, string subject, string? requestedBy);

    DiagJobSnapshot? Get(Guid id);

    /// <summary>The job currently holding the slot, if any.</summary>
    DiagJobSnapshot? Current { get; }

    IReadOnlyList<DiagJobSnapshot> Recent(int limit = 10);

    /// <summary>Ask a running job to stop. Its partial result is kept.</summary>
    bool Cancel(Guid id);
}

/// <summary>Write side of a job, held by the service that runs it.</summary>
public interface IDiagnosticJobHandle : IDisposable
{
    Guid Id { get; }
    /// <summary>Cancelled by <see cref="IDiagnosticJobRegistry.Cancel"/>, by the duration budget, or on daemon shutdown.</summary>
    CancellationToken Token { get; }
    bool CancellationRequested { get; }

    void Progress(int itemCount, bool truncated = false);
    void Complete(TraceResult result);
    void Complete(CaptureResult result);
    void Fail(string message);
}
