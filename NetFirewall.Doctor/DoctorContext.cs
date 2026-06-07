namespace NetFirewall.Doctor;

/// <summary>
/// Shared, read-only state for all checks: resolved deployment paths, parsed env
/// files, and OS info. Built once at startup. Path defaults match deploy/install.sh
/// but are overridable (some hosts use /opt/tekium/... instead of /opt/netfirewall).
/// </summary>
public sealed class DoctorContext
{
    public bool IsLinux { get; init; } = OperatingSystem.IsLinux();

    /// <summary>Install prefix (binaries). Default /opt/netfirewall.</summary>
    public string Prefix { get; init; } = "/opt/netfirewall";

    /// <summary>Config dir holding the env files. Default /etc/netfirewall.</summary>
    public string EtcDir { get; init; } = "/etc/netfirewall";

    /// <summary>Runtime dir (socket). Default /run/netfirewall.</summary>
    public string RunDir { get; init; } = "/run/netfirewall";

    /// <summary>State dir. Default /var/lib/netfirewall.</summary>
    public string StateDir { get; init; } = "/var/lib/netfirewall";

    public string DaemonEnvPath => Path.Combine(EtcDir, "daemon.env");
    public string WebEnvPath => Path.Combine(EtcDir, "web.env");

    /// <summary>Parsed daemon.env (key→value), or null if the file is absent/unreadable.</summary>
    public IReadOnlyDictionary<string, string>? DaemonEnv { get; init; }

    /// <summary>Parsed web.env (key→value), or null if absent/unreadable.</summary>
    public IReadOnlyDictionary<string, string>? WebEnv { get; init; }

    /// <summary>Unix socket path to reach the daemon (from env or default).</summary>
    public string DaemonSocketPath { get; init; } = "/run/netfirewall/control.sock";

    /// <summary>Build a context: resolve paths and parse the env files (fail-soft).</summary>
    public static DoctorContext Build(string? prefix, string? etcDir)
    {
        var etc = etcDir ?? "/etc/netfirewall";
        var daemonEnv = EnvFile.TryParse(Path.Combine(etc, "daemon.env"));
        var webEnv = EnvFile.TryParse(Path.Combine(etc, "web.env"));

        var socket = daemonEnv is not null && daemonEnv.TryGetValue("Daemon__SocketPath", out var s) && !string.IsNullOrWhiteSpace(s)
            ? s
            : "/run/netfirewall/control.sock";

        return new DoctorContext
        {
            Prefix = prefix ?? "/opt/netfirewall",
            EtcDir = etc,
            DaemonEnv = daemonEnv,
            WebEnv = webEnv,
            DaemonSocketPath = socket,
        };
    }
}

/// <summary>
/// Pure, testable parser for systemd-style EnvironmentFile syntax: <c>KEY=VALUE</c>
/// lines, <c>#</c> comments, blank lines ignored. Values are taken verbatim after
/// the first <c>=</c> (no quote stripping — systemd doesn't either for our files).
/// </summary>
public static class EnvFile
{
    public static IReadOnlyDictionary<string, string>? TryParse(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            return Parse(File.ReadAllLines(path));
        }
        catch
        {
            return null; // unreadable (perms) — caller treats as "not present"
        }
    }

    public static IReadOnlyDictionary<string, string> Parse(IEnumerable<string> lines)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0 || line[0] == '#') continue;
            var eq = line.IndexOf('=');
            if (eq <= 0) continue;
            var key = line[..eq].Trim();
            var val = line[(eq + 1)..]; // verbatim, no trim of the value side
            map[key] = val;
        }
        return map;
    }
}
