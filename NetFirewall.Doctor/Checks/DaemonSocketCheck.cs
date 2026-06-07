using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NetFirewall.Services.Daemon;

namespace NetFirewall.Doctor.Checks;

/// <summary>
/// The daemon's Unix socket exists and answers /health. Reuses the production
/// <see cref="DaemonClient"/> over the same socket the Web uses (no auth needed for
/// the health probe).
/// </summary>
public sealed class DaemonSocketCheck : ICheck
{
    public string Category => "Daemon";
    public string Name => "Socket reachable";
    public IReadOnlyList<string> Services => new[] { "daemon" };

    public async Task<CheckResult> RunAsync(DoctorContext ctx, CancellationToken ct)
    {
        if (!ctx.IsLinux)
            return CheckResult.Skip("not applicable off Linux");

        if (!File.Exists(ctx.DaemonSocketPath))
            return CheckResult.Fail(
                $"socket not found at {ctx.DaemonSocketPath}",
                remedy: "Is the daemon running? systemctl status netfirewall-daemon");

        try
        {
            var opts = Options.Create(new DaemonClientOptions
            {
                SocketPath = ctx.DaemonSocketPath,
                Timeout = TimeSpan.FromSeconds(5),
            });
            using var client = new DaemonClient(opts, new NullDaemonSessionTokenProvider(),
                NullLogger<DaemonClient>.Instance);
            var alive = await client.IsAliveAsync(ct);
            return alive
                ? CheckResult.Pass($"daemon answered /health on {ctx.DaemonSocketPath}")
                : CheckResult.Fail("socket present but /health did not respond OK",
                    remedy: "Check daemon logs: journalctl -u netfirewall-daemon");
        }
        catch (Exception ex)
        {
            return CheckResult.Fail($"could not reach daemon: {ex.Message}",
                remedy: "systemctl status netfirewall-daemon; verify socket perms.");
        }
    }
}
