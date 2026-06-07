using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Services.Processes;

namespace NetFirewall.Doctor.Checks;

/// <summary>
/// Something is actually bound to UDP/67 (the BOOTP/DHCP server port), i.e. the
/// DHCP server is up and listening. Uses <c>ss -lunp</c> via the shared
/// <see cref="IProcessRunner"/> (rule #8). Linux-only.
///
/// The DHCP server also opens AF_PACKET raw sockets for L2 receive, which do NOT
/// show up as a UDP/67 bind. So a clear "67 listening" is a strong positive, but
/// we only Warn (not Fail) when it's absent: the systemd check already covers
/// "unit dead", and a raw-socket-only deploy is still functional.
/// </summary>
public sealed class DhcpListeningCheck : ICheck
{
    private readonly IProcessRunner _runner = new ProcessRunner(NullLogger<ProcessRunner>.Instance);

    public string Category => "DHCP";
    public string Name => "Listening on UDP/67";
    public IReadOnlyList<string> Services => new[] { "dhcp" };

    public async Task<CheckResult> RunAsync(DoctorContext ctx, CancellationToken ct)
    {
        if (!ctx.IsLinux)
            return CheckResult.Skip("not applicable off Linux");

        // -l listening, -u UDP, -n numeric, -p process (process needs root; absence is non-fatal).
        var res = await RunSs("-lunp", ct);
        if (res.ExitCode != 0 && string.IsNullOrEmpty(res.Output))
            return CheckResult.Skip($"could not run ss: {res.Error.Trim()}");

        // Match a UDP listener on :67 (covers 0.0.0.0:67, *:67, [::]:67).
        var listening = res.Output
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Any(line =>
            {
                var l = line.Trim();
                return l.Contains(":67 ") || l.EndsWith(":67") || l.Contains(":67\t");
            });

        if (!listening)
            return CheckResult.Warn(
                "nothing bound to UDP/67",
                remedy: "Is the DHCP server running? systemctl status netfirewall-dhcp  (note: a raw-socket-only deploy may not show a :67 UDP bind).");

        return CheckResult.Pass("UDP/67 has a listener");
    }

    private async Task<ProcessResult> RunSs(string args, CancellationToken ct)
    {
        try { return await _runner.RunAsync("ss", args, TimeSpan.FromSeconds(5), ct); }
        catch (Exception ex) { return new ProcessResult(-1, "", ex.Message); }
    }
}
