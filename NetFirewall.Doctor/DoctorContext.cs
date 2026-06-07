using System.Text.Json;

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

    /// <summary>The DHCP server's runtime dir (binary + appsettings.json). Default $Prefix/dhcp-server,
    /// matching deploy/systemd/netfirewall-dhcp.service WorkingDirectory.</summary>
    public string DhcpDir => Path.Combine(Prefix, "dhcp-server");

    /// <summary>Optional EnvironmentFile for the DHCP unit (loaded with a leading '-', so it may be absent).</summary>
    public string DhcpEnvPath => Path.Combine(EtcDir, "dhcp.env");

    /// <summary>Directory holding the .sql migration files. In a deploy the installer copies them to
    /// <c>$Prefix/migrations/sql/migrations</c>; when run from the repo they live under
    /// <c>NetFirewall.Services/sql/migrations</c>. Returns the first that exists, else the deploy path.</summary>
    public string MigrationsDir
    {
        get
        {
            var deployed = Path.Combine(Prefix, "migrations", "sql", "migrations");
            if (Directory.Exists(deployed)) return deployed;
            // Repo fallback: walk up from CWD looking for the services migrations folder.
            var repo = FindRepoMigrationsDir();
            return repo ?? deployed;
        }
    }

    private static string? FindRepoMigrationsDir()
    {
        try
        {
            var dir = new DirectoryInfo(Directory.GetCurrentDirectory());
            for (int i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
            {
                var candidate = Path.Combine(dir.FullName, "NetFirewall.Services", "sql", "migrations");
                if (Directory.Exists(candidate)) return candidate;
            }
        }
        catch { /* best effort */ }
        return null;
    }

    /// <summary>Parsed daemon.env (key→value), or null if the file is absent/unreadable.</summary>
    public IReadOnlyDictionary<string, string>? DaemonEnv { get; init; }

    /// <summary>Parsed web.env (key→value), or null if absent/unreadable.</summary>
    public IReadOnlyDictionary<string, string>? WebEnv { get; init; }

    /// <summary>Parsed dhcp.env (key→value), or null if absent/unreadable. Optional in prod.</summary>
    public IReadOnlyDictionary<string, string>? DhcpEnv { get; init; }

    /// <summary>Unix socket path to reach the daemon (from env or default).</summary>
    public string DaemonSocketPath { get; init; } = "/run/netfirewall/control.sock";

    /// <summary>The DHCP server's effective PostgreSQL connection string, resolving the same
    /// way the running service does: dhcp.env override first, then its appsettings.json. Null if
    /// neither is present/readable.</summary>
    public string? DhcpConnectionString { get; init; }

    /// <summary>The DHCP listening interface(s) the service would fall back to when the DB has no
    /// enabled subnets — resolved from dhcp.env (DHCP__Interfaces / DHCP__Interface) then
    /// appsettings.json (DHCP:Interfaces / DHCP:Interface). Empty if nothing is configured.
    /// NOTE: at runtime, enabled DB subnets take precedence over this config value (see DhcpWorker).</summary>
    public IReadOnlyList<string> DhcpInterfaces { get; init; } = Array.Empty<string>();

    /// <summary>Build a context: resolve paths and parse the env files (fail-soft).</summary>
    public static DoctorContext Build(string? prefix, string? etcDir)
    {
        var pfx = prefix ?? "/opt/netfirewall";
        var etc = etcDir ?? "/etc/netfirewall";
        var daemonEnv = EnvFile.TryParse(Path.Combine(etc, "daemon.env"));
        var webEnv = EnvFile.TryParse(Path.Combine(etc, "web.env"));
        var dhcpEnv = EnvFile.TryParse(Path.Combine(etc, "dhcp.env"));

        var socket = daemonEnv is not null && daemonEnv.TryGetValue("Daemon__SocketPath", out var s) && !string.IsNullOrWhiteSpace(s)
            ? s
            : "/run/netfirewall/control.sock";

        var dhcpAppsettings = DhcpAppsettings.TryParse(Path.Combine(pfx, "dhcp-server", "appsettings.json"));

        return new DoctorContext
        {
            Prefix = pfx,
            EtcDir = etc,
            DaemonEnv = daemonEnv,
            WebEnv = webEnv,
            DhcpEnv = dhcpEnv,
            DaemonSocketPath = socket,
            DhcpConnectionString = ResolveDhcpConnection(dhcpEnv, dhcpAppsettings),
            DhcpInterfaces = ResolveDhcpInterfaces(dhcpEnv, dhcpAppsettings),
        };
    }

    // .NET config layering: an env var (Section__Key) overrides the JSON value, so env wins.
    private static string? ResolveDhcpConnection(
        IReadOnlyDictionary<string, string>? env,
        DhcpAppsettings? appsettings)
    {
        var fromEnv = env?.GetValueOrDefault("ConnectionStrings__DefaultConnection");
        if (!string.IsNullOrWhiteSpace(fromEnv)) return fromEnv;
        return string.IsNullOrWhiteSpace(appsettings?.ConnectionString) ? null : appsettings.ConnectionString;
    }

    private static IReadOnlyList<string> ResolveDhcpInterfaces(
        IReadOnlyDictionary<string, string>? env,
        DhcpAppsettings? appsettings)
    {
        // env override: DHCP__Interfaces__0.. (array) or DHCP__Interface (single).
        if (env is not null)
        {
            var arr = env
                .Where(kv => kv.Key.StartsWith("DHCP__Interfaces__", StringComparison.Ordinal))
                .OrderBy(kv => kv.Key, StringComparer.Ordinal)
                .Select(kv => kv.Value.Trim())
                .Where(v => v.Length > 0)
                .ToList();
            if (arr.Count > 0) return arr;
            var single = env.GetValueOrDefault("DHCP__Interface");
            if (!string.IsNullOrWhiteSpace(single)) return new[] { single.Trim() };
        }

        if (appsettings is not null)
        {
            if (appsettings.Interfaces.Count > 0) return appsettings.Interfaces;
            if (!string.IsNullOrWhiteSpace(appsettings.Interface)) return new[] { appsettings.Interface };
        }

        return Array.Empty<string>();
    }
}

/// <summary>
/// The slice of the DHCP server's appsettings.json the Doctor needs: its connection string
/// and configured listening interface(s). Parsed fail-soft (a missing/malformed file yields null).
/// </summary>
public sealed record DhcpAppsettings(string? ConnectionString, string? Interface, IReadOnlyList<string> Interfaces)
{
    public static DhcpAppsettings? TryParse(string path)
    {
        try
        {
            if (!File.Exists(path)) return null;
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            var root = doc.RootElement;

            string? conn = null;
            if (root.TryGetProperty("ConnectionStrings", out var cs) &&
                cs.TryGetProperty("DefaultConnection", out var dc) && dc.ValueKind == JsonValueKind.String)
                conn = dc.GetString();

            string? iface = null;
            var ifaces = new List<string>();
            if (root.TryGetProperty("DHCP", out var dhcp))
            {
                if (dhcp.TryGetProperty("Interface", out var i) && i.ValueKind == JsonValueKind.String)
                    iface = i.GetString();
                if (dhcp.TryGetProperty("Interfaces", out var arr) && arr.ValueKind == JsonValueKind.Array)
                    foreach (var el in arr.EnumerateArray())
                        if (el.ValueKind == JsonValueKind.String && el.GetString() is { Length: > 0 } v)
                            ifaces.Add(v);
            }

            return new DhcpAppsettings(conn, iface, ifaces);
        }
        catch
        {
            return null; // absent / unreadable / malformed — caller treats as "not present"
        }
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
