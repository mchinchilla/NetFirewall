namespace NetFirewall.Models.Diagnostics;

/// <summary>A doctor run: the ordered checks plus roll-up counters the UI pills show.</summary>
public sealed record DiagReport(
    string Tool,
    string Subject,
    DateTime StartedAtUtc,
    int DurationMs,
    IReadOnlyList<DiagCheck> Checks)
{
    public int PassCount => Checks.Count(c => c.Status == DiagCheckStatus.Pass);
    public int WarnCount => Checks.Count(c => c.Status == DiagCheckStatus.Warn);
    public int FailCount => Checks.Count(c => c.Status == DiagCheckStatus.Fail);
    public int SkipCount => Checks.Count(c => c.Status == DiagCheckStatus.Skip);

    /// <summary>Worst verdict wins; a report made only of skips is itself a skip.</summary>
    public DiagCheckStatus Overall =>
        FailCount > 0 ? DiagCheckStatus.Fail
        : WarnCount > 0 ? DiagCheckStatus.Warn
        : PassCount > 0 ? DiagCheckStatus.Pass
        : DiagCheckStatus.Skip;

    /// <summary>The <c>diag_runs.status</c> value for this report.</summary>
    public string RunStatus => Overall switch
    {
        DiagCheckStatus.Fail => DiagRunStatus.Fail,
        DiagCheckStatus.Warn => DiagRunStatus.Warn,
        _ => DiagRunStatus.Ok,
    };

    public string Summary =>
        $"{PassCount} pass, {WarnCount} warn, {FailCount} fail" + (SkipCount > 0 ? $", {SkipCount} skipped" : "");
}
