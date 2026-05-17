using System.Globalization;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.Monitoring;

[SupportedOSPlatform("linux")]
public sealed partial class WanReachabilityService : IWanReachabilityService
{
    private readonly IFirewallService _firewall;
    private readonly IProcessRunner _runner;
    private readonly ILogger<WanReachabilityService> _logger;

    public WanReachabilityService(
        IFirewallService firewall,
        IProcessRunner runner,
        ILogger<WanReachabilityService> logger)
    {
        _firewall = firewall;
        _runner = runner;
        _logger = logger;
    }

    public async Task<IReadOnlyList<WanReachability>> ProbeAllAsync(CancellationToken ct = default)
    {
        var ifaces = await _firewall.GetInterfacesAsync(ct);
        var wans = ifaces.Where(i =>
            string.Equals(i.Type, "WAN", StringComparison.OrdinalIgnoreCase) &&
            i.Enabled &&
            i.Gateway is not null).ToList();

        // Probe all WANs in parallel. Each ping is bounded at 2s by the
        // -W flag, so the whole call is roughly bounded too.
        var tasks = wans.Select(w => ProbeOneAsync(w.Name, w.Role ?? "", w.Gateway!.ToString(), ct));
        return await Task.WhenAll(tasks);
    }

    private async Task<WanReachability> ProbeOneAsync(string iface, string role, string target, CancellationToken ct)
    {
        try
        {
            // -c 1 (one packet), -W 2 (wait 2s for reply), -I iface (force the
            // probe out the right NIC even if the routing table would pick
            // another). If gateway is unreachable but the WAN itself is up we
            // still want to know — that's the operator's problem to debug, but
            // it's a real state worth showing.
            var result = await _runner.RunAsync(
                "ping",
                $"-c 1 -W 2 -I {iface} {target}",
                TimeSpan.FromSeconds(3),
                ct);

            if (!result.Success)
            {
                return new WanReachability(iface, role, target, false, null, "no reply within 2s");
            }

            // Parse the rtt from the ping line:  "64 bytes from 8.8.8.8: ... time=12.3 ms"
            var match = TimeRx().Match(result.Output);
            double? rtt = match.Success && double.TryParse(
                match.Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var ms) ? ms : null;

            return new WanReachability(iface, role, target, true, rtt, null);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "WAN probe failed for {Iface}", iface);
            return new WanReachability(iface, role, target, false, null, ex.Message);
        }
    }

    [GeneratedRegex(@"time=([\d.]+)\s*ms", RegexOptions.IgnoreCase)]
    private static partial Regex TimeRx();
}
