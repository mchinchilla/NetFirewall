using Microsoft.Extensions.Logging;
using NetFirewall.Models;
using NetFirewall.Models.System;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.Network;

public sealed class StaticRouteApplicator : IStaticRouteApplicator
{
    private readonly IFirewallService _firewall;
    private readonly INetworkConfigResolver _resolver;
    private readonly IProcessRunner _runner;
    private readonly ILogger<StaticRouteApplicator> _logger;

    public StaticRouteApplicator(
        IFirewallService firewall,
        INetworkConfigResolver resolver,
        IProcessRunner runner,
        ILogger<StaticRouteApplicator> logger)
    {
        _firewall = firewall;
        _resolver = resolver;
        _runner = runner;
        _logger = logger;
    }

    public async Task<ServiceResponse<NetworkApplyResult>> ApplyAsync(Guid routeId, CancellationToken ct = default)
    {
        var route = await _firewall.GetStaticRouteByIdAsync(routeId, ct);
        if (route == null) return ServiceResponse<NetworkApplyResult>.Fail("Route not found.");

        var iface = await _firewall.GetInterfaceByIdAsync(route.InterfaceId, ct);
        if (iface == null) return ServiceResponse<NetworkApplyResult>.Fail($"Interface {route.InterfaceId} not found.");

        var allRoutes = (await _firewall.GetStaticRoutesAsync(iface.Id, ct)).Where(r => r.Enabled).ToList();

        // 1. Regenerate the iface's persistent config with all current routes.
        var writer = await _resolver.ResolveAsync(ct);
        var applyResult = await writer.ApplyConfigAsync(iface, allRoutes);

        // 2. Hot-add the route to the live routing table so the user doesn't have to wait
        //    for ifdown/ifup. `replace` is idempotent — it acts as add or update.
        if (applyResult.Success && route.Enabled)
        {
            var gateway = route.Gateway != null ? $"via {route.Gateway} " : string.Empty;
            var hot = await _runner.RunAsync("ip",
                $"route replace {route.Destination} {gateway}dev {iface.Name} metric {route.Metric}", ct: ct);
            if (!hot.Success)
            {
                _logger.LogWarning(
                    "Persistent config applied but live `ip route replace` failed (exit {Code}): {Stderr}",
                    hot.ExitCode, hot.Error.Trim());
            }
        }

        return applyResult.Success
            ? ServiceResponse<NetworkApplyResult>.Ok(applyResult, $"Route {route.Destination} applied.")
            : ServiceResponse<NetworkApplyResult>.Fail(applyResult.Message);
    }

    public async Task<ServiceResponse<NetworkApplyResult>> RemoveAsync(Guid routeId, CancellationToken ct = default)
    {
        var route = await _firewall.GetStaticRouteByIdAsync(routeId, ct);
        if (route == null) return ServiceResponse<NetworkApplyResult>.Fail("Route not found.");

        var iface = await _firewall.GetInterfaceByIdAsync(route.InterfaceId, ct);
        if (iface == null) return ServiceResponse<NetworkApplyResult>.Fail($"Interface {route.InterfaceId} not found.");

        // 1. Remove from live routing table (best effort — may already be gone).
        var hot = await _runner.RunAsync("ip", $"route del {route.Destination} dev {iface.Name}", ct: ct);
        if (!hot.Success)
        {
            _logger.LogDebug("ip route del returned {Code} (may already be removed)", hot.ExitCode);
        }

        // 2. Persistent config: delete the route from DB, then regenerate iface config
        //    so it doesn't come back at next boot.
        await _firewall.DeleteStaticRouteAsync(routeId, ct);

        var remaining = (await _firewall.GetStaticRoutesAsync(iface.Id, ct)).Where(r => r.Enabled).ToList();
        var writer = await _resolver.ResolveAsync(ct);
        var applyResult = await writer.ApplyConfigAsync(iface, remaining);

        return applyResult.Success
            ? ServiceResponse<NetworkApplyResult>.Ok(applyResult, $"Route {route.Destination} removed.")
            : ServiceResponse<NetworkApplyResult>.Fail(applyResult.Message);
    }
}
