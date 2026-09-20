using Microsoft.Extensions.Logging;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Firewall;

namespace NetFirewall.Services.Vpn;

public sealed class WireGuardBringUpService : IWireGuardBringUpService
{
    private readonly IWireGuardApplyService _apply;
    private readonly IPolicyRoutingApplyService _routing;
    private readonly ILogger<WireGuardBringUpService> _logger;

    public WireGuardBringUpService(
        IWireGuardApplyService apply,
        IPolicyRoutingApplyService routing,
        ILogger<WireGuardBringUpService> logger)
    {
        _apply = apply;
        _routing = routing;
        _logger = logger;
    }

    public async Task<WireGuardBringUpResult> ApplyAsync(WgServer server, IReadOnlyList<WgPeer> peers, CancellationToken ct = default)
    {
        var apply = await _apply.ApplyAsync(server, peers, ct);
        if (!apply.Success)
            return new WireGuardBringUpResult { Apply = apply };

        // Stop deleted the netdevice, and with it every `dev <iface>` route in
        // every table; wg-quick (Table=off) puts none back. The fwmark rule
        // survived, so lookups hit an empty table and fall through to main:
        // the tunnel shows "connected" while nothing rides it. Re-install the
        // tunnel's own routes now that the device exists again. Idempotent
        // (`ip route replace`), so a hot reload pays nothing.
        var routing = await _routing.ReapplyRoutesForDeviceAsync(server.Name, ct);
        if (routing.Success)
            _logger.LogInformation("WireGuard {Name}: {Count} policy route(s) re-applied after bring-up",
                server.Name, routing.Steps.Count(s => s.Phase == "ip-route" && s.Success));
        else
            _logger.LogWarning("WireGuard {Name} is up but its policy routes were not re-applied: {Error}",
                server.Name, routing.Error);

        return new WireGuardBringUpResult { Apply = apply, Routing = routing };
    }
}
