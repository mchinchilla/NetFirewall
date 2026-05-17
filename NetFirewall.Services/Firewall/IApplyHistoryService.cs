namespace NetFirewall.Services.Firewall;

/// <summary>
/// Records every Apply (nftables / tc / wireguard) and answers "is the DB
/// ahead of the running kernel?". Compares <c>fw_audit_log.created_at</c>
/// against the last successful apply of each kind to detect pending changes.
/// </summary>
public interface IApplyHistoryService
{
    /// <summary>Persist an apply attempt. Called from the daemon endpoint after the actual work.</summary>
    Task RecordAsync(string kind, bool success, int? exitCode, string? message, string? appliedBy, CancellationToken ct = default);

    /// <summary>Last successful apply timestamp for a given kind (null = never applied).</summary>
    Task<DateTime?> LastSuccessAsync(string kind, CancellationToken ct = default);

    /// <summary>Pending-change report — one entry per kind with optional last apply + pending count.</summary>
    Task<IReadOnlyList<PendingChangesSummary>> GetPendingSummaryAsync(CancellationToken ct = default);

    /// <summary>Last N apply attempts (any kind), newest first. For dashboard "recent applies".</summary>
    Task<IReadOnlyList<ApplyHistoryEntry>> RecentAsync(int limit = 10, CancellationToken ct = default);
}

public sealed record ApplyHistoryEntry(
    Guid Id,
    string Kind,
    bool Success,
    DateTime AppliedAt,
    string? AppliedBy,
    int? ExitCode,
    string? Message);

/// <summary>
/// Per-kind pending count. <c>PendingCount</c> = rows in the relevant fw_*
/// tables whose <c>updated_at</c> (or <c>created_at</c> if no updated_at) is
/// newer than <c>LastAppliedAt</c>. Null LastAppliedAt means "never applied"
/// and PendingCount is the total enabled row count.
/// </summary>
public sealed record PendingChangesSummary(
    string Kind,
    DateTime? LastAppliedAt,
    int PendingCount);
