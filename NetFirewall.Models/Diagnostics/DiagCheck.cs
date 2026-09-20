using System.Text.Json.Serialization;

namespace NetFirewall.Models.Diagnostics;

/// <summary>Verdict of one diagnostic check. Serialised by name so <c>diag_runs.result</c> stays readable.</summary>
[JsonConverter(typeof(JsonStringEnumConverter))]
public enum DiagCheckStatus
{
    Pass,
    Warn,
    Fail,
    /// <summary>Not applicable, not available on this platform, or timed out — never a verdict.</summary>
    Skip
}

/// <summary>What the check actually ran and saw — shown under "evidence" in the UI.</summary>
public sealed record DiagEvidence(string Command, string Output, bool Truncated = false);

/// <summary>How to fix it. <see cref="Href"/> deep-links to the page/button that applies the fix when one exists.</summary>
public sealed record DiagRemedy(string Label, string? Href = null, string? Hint = null);

/// <summary>
/// One row of a doctor report. Pure data: produced by the daemon, persisted as
/// JSON, rendered by <c>_DiagCheckList</c> for every doctor (VPN today, WAN/DHCP/DNS later).
/// </summary>
public sealed record DiagCheck(
    string Id,
    string Category,
    string Title,
    DiagCheckStatus Status,
    string Summary,
    string? Detail = null,
    DiagRemedy? Remedy = null,
    IReadOnlyList<DiagEvidence>? Evidence = null,
    int DurationMs = 0)
{
    public static DiagCheck Pass(string id, string category, string title, string summary,
        string? detail = null, IReadOnlyList<DiagEvidence>? evidence = null) =>
        new(id, category, title, DiagCheckStatus.Pass, summary, detail, null, evidence);

    public static DiagCheck Warn(string id, string category, string title, string summary,
        DiagRemedy? remedy = null, string? detail = null, IReadOnlyList<DiagEvidence>? evidence = null) =>
        new(id, category, title, DiagCheckStatus.Warn, summary, detail, remedy, evidence);

    public static DiagCheck Fail(string id, string category, string title, string summary,
        DiagRemedy? remedy = null, string? detail = null, IReadOnlyList<DiagEvidence>? evidence = null) =>
        new(id, category, title, DiagCheckStatus.Fail, summary, detail, remedy, evidence);

    public static DiagCheck Skip(string id, string category, string title, string summary,
        string? detail = null) =>
        new(id, category, title, DiagCheckStatus.Skip, summary, detail);
}
