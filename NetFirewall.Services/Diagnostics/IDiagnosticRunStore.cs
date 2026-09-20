using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics;

/// <summary>
/// Persistence for <c>diag_runs</c>. The daemon calls Start/Finish around every
/// tool run; the Web uses the read/purge half for the History page (it reads the
/// table directly so history works while the daemon is down).
/// </summary>
public interface IDiagnosticRunStore
{
    /// <summary>Insert a <c>running</c> row and return its id. <paramref name="parameters"/> is serialised as JSON (redact secrets first).</summary>
    Task<Guid> StartAsync(string tool, string? target, string? requestedBy, object? parameters, CancellationToken ct = default);

    /// <summary>Complete the row. <paramref name="result"/> is serialised as JSON; results over the size cap are replaced by a truncation marker.</summary>
    Task FinishAsync(Guid id, string status, object? result, string? summary, CancellationToken ct = default);

    Task<DiagRun?> GetAsync(Guid id, CancellationToken ct = default);

    Task<(IReadOnlyList<DiagRun> Rows, int Total)> ListAsync(DiagRunFilter filter, int page, int pageSize, CancellationToken ct = default);

    Task<IReadOnlyList<DiagRun>> RecentAsync(int limit, CancellationToken ct = default);

    /// <summary>Delete rows started more than <paramref name="age"/> ago. Returns the count.</summary>
    Task<int> PurgeOlderThanAsync(TimeSpan age, CancellationToken ct = default);

    Task<int> PurgeAllAsync(CancellationToken ct = default);
}
