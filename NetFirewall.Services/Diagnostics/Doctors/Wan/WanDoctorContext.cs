using NetFirewall.Models.Diagnostics;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.WanMonitor;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.WanMonitor;

namespace NetFirewall.Services.Diagnostics.Doctors.Wan;

/// <summary>
/// Everything the WAN doctor may ask about the box's uplinks, fetched at most
/// once per run. Dual-WAN failures are almost always a disagreement between three
/// sources of truth — the database, the kernel's policy routing, and what the
/// health monitor believes — so the context holds all three side by side.
/// </summary>
public sealed class WanDoctorContext
{
    private readonly Lazy<Task<IReadOnlyList<FwInterface>>> _interfaces;
    private readonly Lazy<Task<IReadOnlyList<WanHealthConfig>>> _configs;
    private readonly Lazy<Task<IReadOnlyList<WanHealthState>>> _state;
    private readonly Lazy<Task<WanFailoverControl>> _control;
    private readonly Lazy<Task<IReadOnlyList<IpRuleEntry>>> _ipRules;
    private readonly Lazy<Task<IReadOnlyList<IpRouteEntry>>> _mainRoutes;
    private readonly Lazy<Task<IReadOnlyList<InterfaceHealth>>> _links;

    public IRouteOracleService Routes { get; }
    public IPingProbeService Probes { get; }
    public string ProbeTarget { get; }

    internal WanDoctorContext(
        string probeTarget,
        IFirewallService fw,
        IWanHealthService health,
        IRouteOracleService routes,
        IInterfaceHealthService links,
        IPingProbeService probes,
        CancellationToken ct)
    {
        ProbeTarget = probeTarget;
        Routes = routes;
        Probes = probes;

        _interfaces = new(() => fw.GetInterfacesAsync(ct));
        _configs    = new(() => health.GetAllConfigsAsync(ct));
        _state      = new(() => health.GetStateAsync(ct));
        _control    = new(() => health.GetControlAsync(ct));
        _ipRules    = new(() => routes.ListRulesAsync(ct));
        _mainRoutes = new(() => routes.ShowTableAsync("main", ct));
        _links      = new(() => links.GetAllAsync(ct));
    }

    public Task<IReadOnlyList<FwInterface>> InterfacesAsync() => _interfaces.Value;
    public Task<IReadOnlyList<WanHealthConfig>> ConfigsAsync() => _configs.Value;
    public Task<IReadOnlyList<WanHealthState>> StateAsync() => _state.Value;
    public Task<WanFailoverControl> ControlAsync() => _control.Value;
    public Task<IReadOnlyList<IpRuleEntry>> IpRulesAsync() => _ipRules.Value;
    public Task<IReadOnlyList<IpRouteEntry>> MainRoutesAsync() => _mainRoutes.Value;
    public Task<IReadOnlyList<InterfaceHealth>> LinksAsync() => _links.Value;

    public async Task<IReadOnlyList<FwInterface>> WansAsync() =>
        (await InterfacesAsync()).Where(i => string.Equals(i.Type, "WAN", StringComparison.OrdinalIgnoreCase) && i.Enabled)
            .OrderBy(i => i.Name, StringComparer.Ordinal).ToList();

    /// <summary>The default route currently installed in <c>main</c> — the uplink unmarked traffic uses.</summary>
    public async Task<IpRouteEntry?> DefaultRouteAsync() =>
        (await MainRoutesAsync()).FirstOrDefault(r => r.Destination is "default" or "0.0.0.0/0");
}

public interface IWanDoctorContextFactory
{
    WanDoctorContext Create(string probeTarget, CancellationToken ct);
}

public sealed class WanDoctorContextFactory : IWanDoctorContextFactory
{
    private readonly IFirewallService _fw;
    private readonly IWanHealthService _health;
    private readonly IRouteOracleService _routes;
    private readonly IInterfaceHealthService _links;
    private readonly IPingProbeService _probes;

    public WanDoctorContextFactory(IFirewallService fw, IWanHealthService health, IRouteOracleService routes, IInterfaceHealthService links, IPingProbeService probes)
    {
        _fw = fw; _health = health; _routes = routes; _links = links; _probes = probes;
    }

    public WanDoctorContext Create(string probeTarget, CancellationToken ct) =>
        new(probeTarget, _fw, _health, _routes, _links, _probes, ct);
}

public interface IWanDoctorCheck : IDoctorCheck<WanDoctorContext> { }
public abstract class WanDoctorCheckBase : DoctorCheckBase<WanDoctorContext>, IWanDoctorCheck { }

/// <summary>Remedy deep-links for WAN findings.</summary>
public static class WanRemedies
{
    public static DiagRemedy Failover(string? hint = null) => new("WAN failover", "/Network/WanFailover", hint);
    public static DiagRemedy PolicyRouting(string? hint = null) => new("Re-apply policy routing", "/Firewall/Apply", hint ?? "Firewall → Apply → Policy routing → Execute.");
    public static DiagRemedy Interfaces(string? hint = null) => new("Network interfaces", "/Network", hint);
    public static DiagRemedy MangleRules(string? hint = null) => new("Mangle rules", "/Firewall/MangleRules", hint);
}
