using NetFirewall.Models.System;

namespace NetFirewall.Web.Auth;

/// <summary>
/// Cheap accessor for runtime metadata shown on the login page system-info card
/// and the layout footer (rule #8 — no static helpers for things that touch
/// process state).
/// </summary>
public interface IAppInfoService
{
    DateTimeOffset StartedAt { get; }
    TimeSpan Uptime { get; }
    string Version { get; }
    /// <summary>Version, commit and release/dirty flags of this build.</summary>
    BuildInfo Build { get; }
    string MachineName { get; }
    string Environment { get; }

    /// <summary>Project repository (config <c>App:RepositoryUrl</c>).</summary>
    string RepositoryUrl { get; }
    /// <summary>The GitHub Release page when this is a release build, else null.</summary>
    string? ReleaseUrl { get; }
    /// <summary>The exact commit this build came from, when known.</summary>
    string? CommitUrl { get; }
    /// <summary>The project docs folder in the repository.</summary>
    string DocsUrl { get; }
}

public sealed class AppInfoService : IAppInfoService
{
    public const string DefaultRepositoryUrl = "https://github.com/mchinchilla/NetFirewall";

    public DateTimeOffset StartedAt { get; }
    public BuildInfo Build { get; }
    public string Version => Build.Version;
    public string MachineName { get; }
    public string Environment { get; }
    public string RepositoryUrl { get; }
    public string? ReleaseUrl { get; }
    public string? CommitUrl { get; }
    public string DocsUrl { get; }

    public AppInfoService(Microsoft.Extensions.Hosting.IHostEnvironment env, IConfiguration config)
    {
        StartedAt = DateTimeOffset.UtcNow;
        Build = BuildVersionText.Info(typeof(AppInfoService).Assembly);
        MachineName = System.Environment.MachineName;
        Environment = env.EnvironmentName;

        var repo = config["App:RepositoryUrl"];
        RepositoryUrl = string.IsNullOrWhiteSpace(repo) ? DefaultRepositoryUrl : repo.TrimEnd('/');
        ReleaseUrl = Build.IsRelease ? $"{RepositoryUrl}/releases/tag/v{Build.Version}" : null;
        CommitUrl = Build.Commit is { } sha ? $"{RepositoryUrl}/commit/{sha}" : null;
        DocsUrl = $"{RepositoryUrl}/tree/master/docs";
    }

    public TimeSpan Uptime => DateTimeOffset.UtcNow - StartedAt;
}
