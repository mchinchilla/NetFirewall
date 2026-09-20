using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Services.Processes;

namespace NetFirewall.Doctor.Checks;

/// <summary>
/// The binaries the Diagnostics section shells out to (see docs/diagnostics.md).
/// Missing ones are a Warn, not a Fail: the firewall itself keeps working, only
/// the matching diagnostic tool reports "not installed". <c>ping</c> and
/// <c>conntrack</c> are Depends of the .deb, the rest are Recommends — a manual
/// install on a minimal host is exactly where this check earns its keep.
/// </summary>
public sealed class DiagnosticToolsCheck : ICheck
{
    private static readonly (string Binary, string Package, string UsedBy, bool Core)[] Tools =
    [
        ("ping",       "iputils-ping", "Ping, traceroute-by-mark, VPN data-plane probe", true),
        ("ip",         "iproute2",     "Route oracle, interface and neighbour panels",   true),
        ("conntrack",  "conntrack",    "Conntrack lookup",                                true),
        ("journalctl", "systemd",      "Drop-log explorer",                               true),
        ("nft",        "nftables",     "VPN doctor firewall checks (live ruleset)",       true),
        ("wg",         "wireguard-tools", "VPN doctor handshake checks",                  false),
        ("traceroute", "traceroute",   "Traceroute without a mark",                       false),
        ("tcpdump",    "tcpdump",      "Packet capture",                                  false),
    ];

    private readonly IProcessRunner _runner = new ProcessRunner(NullLogger<ProcessRunner>.Instance);

    public string Category => "Diagnostics";
    public string Name => "Tool binaries present";
    public IReadOnlyList<string> Services => new[] { "daemon" };

    public async Task<CheckResult> RunAsync(DoctorContext ctx, CancellationToken ct)
    {
        if (!ctx.IsLinux)
            return CheckResult.Skip("not applicable off Linux");

        var missing = new List<(string Binary, string Package, string UsedBy, bool Core)>();
        foreach (var tool in Tools)
        {
            if (!await ExistsAsync(tool.Binary, ct)) missing.Add(tool);
        }

        if (missing.Count == 0)
            return CheckResult.Pass($"all {Tools.Length} diagnostic binaries on PATH");

        var detail = string.Join('\n', missing.Select(m => $"  {m.Binary,-11} ({m.Package}) — {m.UsedBy}"));
        var packages = string.Join(' ', missing.Select(m => m.Package).Distinct());
        return CheckResult.Warn(
            $"{missing.Count} diagnostic binar{(missing.Count == 1 ? "y is" : "ies are")} missing" +
            (missing.Any(m => m.Core) ? " (including core tools)" : " (optional tools)"),
            remedy: $"apt-get install -y {packages}",
            detail: detail);
    }

    private async Task<bool> ExistsAsync(string binary, CancellationToken ct)
    {
        try
        {
            var res = await _runner.RunAsync("command", new[] { "-v", binary }, TimeSpan.FromSeconds(3), ct);
            if (res.Success) return true;
        }
        catch
        {
            // `command` is a shell builtin, not a file — fall through to the PATH scan.
        }

        var path = Environment.GetEnvironmentVariable("PATH") ?? "/usr/sbin:/usr/bin:/sbin:/bin";
        return path.Split(':', StringSplitOptions.RemoveEmptyEntries)
            .Any(dir =>
            {
                try { return File.Exists(Path.Combine(dir, binary)); }
                catch { return false; }
            });
    }
}
