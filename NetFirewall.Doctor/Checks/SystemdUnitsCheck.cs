using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Services.Processes;

namespace NetFirewall.Doctor.Checks;

/// <summary>
/// Each NetFirewall systemd unit is enabled + active. Uses the shared
/// <see cref="IProcessRunner"/> (rule #8) to shell out to systemctl. Linux-only.
/// </summary>
public sealed class SystemdUnitsCheck : ICheck
{
    private static readonly string[] Units = { "netfirewall-daemon", "netfirewall-web" };
    private readonly IProcessRunner _runner = new ProcessRunner(NullLogger<ProcessRunner>.Instance);

    public string Category => "systemd";
    public string Name => "Units enabled + active";
    public IReadOnlyList<string> Services => Array.Empty<string>();

    public async Task<CheckResult> RunAsync(DoctorContext ctx, CancellationToken ct)
    {
        if (!ctx.IsLinux)
            return CheckResult.Skip("not applicable off Linux");

        var problems = new List<string>();
        foreach (var unit in Units)
        {
            var active = await Systemctl($"is-active {unit}", ct);
            if (active.Output.Trim() != "active")
                problems.Add($"{unit} not active ({active.Output.Trim()})");
        }

        if (problems.Count > 0)
            return CheckResult.Fail(
                string.Join("; ", problems),
                remedy: "systemctl status netfirewall-daemon netfirewall-web — then restart/enable as needed.");

        return CheckResult.Pass($"{string.Join(", ", Units)} active");
    }

    private async Task<ProcessResult> Systemctl(string args, CancellationToken ct)
    {
        try { return await _runner.RunAsync("systemctl", args, TimeSpan.FromSeconds(5), ct); }
        catch (Exception ex) { return new ProcessResult(1, "", ex.Message); }
    }
}
