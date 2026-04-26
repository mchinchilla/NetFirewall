namespace NetFirewall.Web.Auth;

/// <summary>
/// Cheap accessor for runtime metadata shown on the login page system-info card
/// (rule #8 — no static helpers for things that touch process state).
/// </summary>
public interface IAppInfoService
{
    DateTimeOffset StartedAt { get; }
    TimeSpan Uptime { get; }
    string Version { get; }
    string MachineName { get; }
    string Environment { get; }
}

public sealed class AppInfoService : IAppInfoService
{
    public DateTimeOffset StartedAt { get; }
    public string Version { get; }
    public string MachineName { get; }
    public string Environment { get; }

    public AppInfoService(Microsoft.Extensions.Hosting.IHostEnvironment env)
    {
        StartedAt = DateTimeOffset.UtcNow;
        Version = typeof(AppInfoService).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
        MachineName = System.Environment.MachineName;
        Environment = env.EnvironmentName;
    }

    public TimeSpan Uptime => DateTimeOffset.UtcNow - StartedAt;
}
