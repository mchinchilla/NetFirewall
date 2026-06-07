using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Services.Processes;

namespace NetFirewall.Doctor.Checks;

/// <summary>
/// Each NetFirewall systemd unit is enabled + active. Uses the shared
/// <see cref="IProcessRunner"/> (rule #8) to shell out to systemctl. Linux-only.
///
/// netfirewall-daemon + netfirewall-web are required (a dead one Fails). The DHCP
/// unit is opt-in (installer-gated behind INSTALL_DHCP=yes), so a not-installed or
/// inactive netfirewall-dhcp only Warns. A unit that IS installed but failed/crashed
/// is surfaced distinctly from one that was never installed.
/// </summary>
public sealed class SystemdUnitsCheck : ICheck
{
    private static readonly string[] RequiredUnits = { "netfirewall-daemon", "netfirewall-web" };
    private const string DhcpUnit = "netfirewall-dhcp";
    private readonly IProcessRunner _runner = new ProcessRunner(NullLogger<ProcessRunner>.Instance);

    public string Category => "systemd";
    public string Name => "Units enabled + active";
    public IReadOnlyList<string> Services => Array.Empty<string>();

    public async Task<CheckResult> RunAsync(DoctorContext ctx, CancellationToken ct)
    {
        if (!ctx.IsLinux)
            return CheckResult.Skip("not applicable off Linux");

        var problems = new List<string>();
        foreach (var unit in RequiredUnits)
        {
            var active = await Systemctl($"is-active {unit}", ct);
            if (active.Output.Trim() != "active")
                problems.Add($"{unit} not active ({active.Output.Trim()})");
        }

        if (problems.Count > 0)
            return CheckResult.Fail(
                string.Join("; ", problems),
                remedy: "systemctl status netfirewall-daemon netfirewall-web — then restart/enable as needed.");

        // DHCP is optional. is-active reports "active" / "inactive" / "failed";
        // a never-installed unit reports "inactive"/"unknown" with a non-zero exit.
        var dhcp = (await Systemctl($"is-active {DhcpUnit}", ct)).Output.Trim();
        if (dhcp == "active")
            return CheckResult.Pass($"{string.Join(", ", RequiredUnits)}, {DhcpUnit} active");
        if (dhcp == "failed")
            return CheckResult.Warn(
                $"{string.Join(", ", RequiredUnits)} active; {DhcpUnit} is failed",
                remedy: $"systemctl status {DhcpUnit}; journalctl -u {DhcpUnit}");

        return CheckResult.Warn(
            $"{string.Join(", ", RequiredUnits)} active; {DhcpUnit} not running ({dhcp})",
            remedy: $"DHCP is optional. To enable it: install {DhcpUnit}.service and systemctl enable --now {DhcpUnit}.");
    }

    private async Task<ProcessResult> Systemctl(string args, CancellationToken ct)
    {
        try { return await _runner.RunAsync("systemctl", args, TimeSpan.FromSeconds(5), ct); }
        catch (Exception ex) { return new ProcessResult(1, "", ex.Message); }
    }
}
