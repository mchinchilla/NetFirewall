namespace NetFirewall.Doctor.Checks;

/// <summary>
/// The DHCP server has a usable configuration: an effective connection string
/// (dhcp.env override or appsettings.json) and at least one listening interface
/// configured as a fallback. Pure config-file inspection — no host/DB access, so
/// it runs on every platform.
/// </summary>
public sealed class DhcpConfigCheck : ICheck
{
    public string Category => "DHCP";
    public string Name => "Configuration";
    public IReadOnlyList<string> Services => new[] { "dhcp" };

    private static readonly string[] Placeholders = { "__REPLACE__", "__REPLACE_MASTER_KEY__", "placeholder", "" };

    public Task<CheckResult> RunAsync(DoctorContext ctx, CancellationToken ct)
    {
        // If neither config source produced anything, the server isn't configured here.
        var hasAppsettings = File.Exists(Path.Combine(ctx.DhcpDir, "appsettings.json"));
        if (ctx.DhcpConnectionString is null && ctx.DhcpInterfaces.Count == 0 && !hasAppsettings && ctx.DhcpEnv is null)
            return Task.FromResult(CheckResult.Skip(
                $"no DHCP config found ({ctx.DhcpDir}/appsettings.json and {ctx.DhcpEnvPath} both absent)"));

        var problems = new List<string>();

        var conn = ctx.DhcpConnectionString;
        if (string.IsNullOrWhiteSpace(conn) || Placeholders.Any(p => conn.Trim() == p) || conn.Contains("__REPLACE__"))
            problems.Add("ConnectionStrings:DefaultConnection missing or still a placeholder");

        if (ctx.DhcpInterfaces.Count == 0)
            problems.Add("no DHCP:Interface / DHCP:Interfaces configured (and DB has no enabled subnet to fall back from)");

        if (problems.Count > 0)
            return Task.FromResult(CheckResult.Fail(
                string.Join("; ", problems),
                remedy: $"Set DHCP:Interface(s) + ConnectionStrings:DefaultConnection in {ctx.DhcpDir}/appsettings.json or override via {ctx.DhcpEnvPath}."));

        return Task.FromResult(CheckResult.Pass(
            $"connection string set; interface(s): {string.Join(", ", ctx.DhcpInterfaces)}"));
    }
}
