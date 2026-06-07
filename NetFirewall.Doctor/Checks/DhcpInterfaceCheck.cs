using System.Net.NetworkInformation;

namespace NetFirewall.Doctor.Checks;

/// <summary>
/// Each interface the DHCP server is configured to listen on actually exists on
/// this host. Linux-only (interface names like ens256 are host-specific).
///
/// This is a Warn, not a Fail: at runtime enabled DB subnets take precedence over
/// the config value (see DhcpWorker.InitializeAsync), so a missing configured
/// interface only bites when the DB has no enabled subnet to fall back from.
/// </summary>
public sealed class DhcpInterfaceCheck : ICheck
{
    public string Category => "DHCP";
    public string Name => "Interface exists on host";
    public IReadOnlyList<string> Services => new[] { "dhcp" };

    public Task<CheckResult> RunAsync(DoctorContext ctx, CancellationToken ct)
    {
        if (!ctx.IsLinux)
            return Task.FromResult(CheckResult.Skip("not applicable off Linux"));

        if (ctx.DhcpInterfaces.Count == 0)
            return Task.FromResult(CheckResult.Skip("no interface configured (see DHCP Configuration check)"));

        HashSet<string> present;
        try
        {
            present = NetworkInterface.GetAllNetworkInterfaces()
                .Select(n => n.Name)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
        }
        catch (Exception ex)
        {
            return Task.FromResult(CheckResult.Skip($"could not enumerate host interfaces: {ex.Message}"));
        }

        var missing = ctx.DhcpInterfaces.Where(i => !present.Contains(i)).ToList();
        if (missing.Count > 0)
            return Task.FromResult(CheckResult.Warn(
                $"configured interface(s) not found on host: {string.Join(", ", missing)}",
                remedy: $"Fix DHCP:Interface(s) to a real NIC (have: {string.Join(", ", present.Order())}), or ensure an enabled DB subnet binds the listening interface."));

        return Task.FromResult(CheckResult.Pass(
            $"all configured interface(s) present: {string.Join(", ", ctx.DhcpInterfaces)}"));
    }
}
