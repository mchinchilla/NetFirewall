namespace NetFirewall.Doctor.Checks;

/// <summary>
/// The DHCP server is deployed: its runtime dir, the published binary, and
/// appsettings.json all exist under <c>$Prefix/dhcp-server</c> (the unit's
/// WorkingDirectory). Linux-only.
///
/// NOTE: DHCP is opt-in — every release bundle ships the binaries, but deploy/setup.sh
/// installs its unit only with --with-dhcp (it binds UDP/67). A release dir without
/// dhcp-server/ (hand-built or legacy) Warns rather than Fails.
/// </summary>
public sealed class DhcpPathsCheck : ICheck
{
    public string Category => "Paths";
    public string Name => "DHCP server deployed";
    public IReadOnlyList<string> Services => new[] { "dhcp" };

    public Task<CheckResult> RunAsync(DoctorContext ctx, CancellationToken ct)
    {
        if (!ctx.DhcpEnabled)
            return Task.FromResult(CheckResult.Skip(DoctorContext.DhcpNotEnabled));

        if (!ctx.IsLinux)
            return Task.FromResult(CheckResult.Skip("not applicable off Linux"));

        if (!Directory.Exists(ctx.DhcpDir))
            return Task.FromResult(CheckResult.Warn(
                $"DHCP server not deployed ({ctx.DhcpDir} absent)",
                remedy: $"dotnet publish -c Release -r linux-x64 -o {ctx.DhcpDir} NetFirewall.DhcpServer, then install netfirewall-dhcp.service."));

        var binary = Path.Combine(ctx.DhcpDir, "NetFirewall.DhcpServer");
        var appsettings = Path.Combine(ctx.DhcpDir, "appsettings.json");

        var missing = new List<string>();
        if (!File.Exists(binary)) missing.Add("NetFirewall.DhcpServer (binary)");
        if (!File.Exists(appsettings)) missing.Add("appsettings.json");

        if (missing.Count > 0)
            return Task.FromResult(CheckResult.Fail(
                $"{ctx.DhcpDir} exists but is incomplete: missing {string.Join(", ", missing)}",
                remedy: $"Re-publish: dotnet publish -c Release -r linux-x64 -o {ctx.DhcpDir} NetFirewall.DhcpServer."));

        return Task.FromResult(CheckResult.Pass($"binary + appsettings.json present under {ctx.DhcpDir}"));
    }
}
