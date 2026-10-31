using System.Text.RegularExpressions;
using NetFirewall.Models.System;
using NetFirewall.Web.Auth;

namespace NetFirewall.Web.Models.Shared;

/// <summary>
/// Typed model for <c>_VersionBadge</c>: the build's version pill (linked to its
/// GitHub Release), its commit chip (linked to the commit) and, when they apply,
/// a "modified" chip for a dirty tree and the environment for non-production hosts.
/// </summary>
public sealed partial class VersionBadgeViewModel
{
    public required BuildInfo Build { get; init; }
    public string? ReleaseUrl { get; init; }
    public string? CommitUrl { get; init; }
    public required string Environment { get; init; }

    /// <summary>
    /// What the pill prints. A release is just <c>0.6.1</c>; past a tag, git describe's
    /// <c>0.6.1-3-g97f88aa-dirty</c> becomes <c>0.6.1+3</c> — the SHA has its own chip
    /// and "dirty" its own warning.
    /// </summary>
    public string DisplayVersion => DescribeTail().Replace(Build.Version, m =>
        m.Groups["ahead"].Success ? $"+{m.Groups["ahead"].Value}" : "");

    /// <summary>Tooltip with the full, unshortened build identity.</summary>
    public string Title => Build.Commit is { } sha
        ? $"NetFirewall {Build.Version} · commit {sha}"
        : $"NetFirewall {Build.Version}";

    /// <summary>Where the pill links: the Release page, else the commit, else nowhere.</summary>
    public string? VersionUrl => ReleaseUrl ?? CommitUrl;

    /// <summary>No tag yet means the version already is the SHA: don't print it twice.</summary>
    public bool ShowCommit => Build.Commit is not null && DisplayVersion != Build.Commit;

    public bool ShowEnvironment => !string.Equals(Environment, "Production", StringComparison.OrdinalIgnoreCase);

    public static VersionBadgeViewModel From(IAppInfoService app) => new()
    {
        Build = app.Build,
        ReleaseUrl = app.ReleaseUrl,
        CommitUrl = app.CommitUrl,
        Environment = app.Environment,
    };

    // "-3-g97f88aa", "-3-g97f88aa-dirty", "-dirty" at the end of a describe string.
    [GeneratedRegex(@"(?:-(?<ahead>\d+)-g[0-9a-f]{7,40})?(?:-dirty)?$")]
    private static partial Regex DescribeTail();
}
