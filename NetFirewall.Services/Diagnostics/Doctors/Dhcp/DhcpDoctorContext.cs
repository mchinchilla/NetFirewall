using NetFirewall.Models.Dhcp;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Dhcp;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Monitoring;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.Diagnostics.Doctors.Dhcp;

/// <summary>
/// State for the DHCP doctor. The DHCP server is an optional, separately-installed
/// unit, so every check has to tolerate it being absent: "not deployed" is a Skip,
/// not a failure.
/// </summary>
public sealed class DhcpDoctorContext
{
    private readonly Lazy<Task<IReadOnlyList<DhcpSubnet>>> _subnets;
    private readonly Lazy<Task<IReadOnlyList<DhcpPool>>> _pools;
    private readonly Lazy<Task<IReadOnlyList<DhcpLease>>> _leases;
    private readonly Lazy<Task<IReadOnlyList<FwInterface>>> _interfaces;
    private readonly Lazy<Task<IReadOnlyList<ServiceHealth>>> _units;
    private readonly Lazy<Task<IReadOnlyList<InterfaceHealth>>> _links;
    private readonly Lazy<Task<string>> _listeners;

    internal DhcpDoctorContext(
        IDhcpAdminService dhcp,
        IFirewallService fw,
        ISystemServiceHealthService units,
        IInterfaceHealthService links,
        IProcessRunner runner,
        DiagnosticsOptions opts,
        CancellationToken ct)
    {
        _subnets    = new(() => dhcp.GetSubnetsAsync(ct));
        _pools      = new(() => dhcp.GetPoolsAsync(null, ct));
        _leases     = new(() => dhcp.GetAllLeasesAsync(includeExpired: false, null, ct));
        _interfaces = new(() => fw.GetInterfacesAsync(ct));
        _units      = new(() => units.GetAllAsync(ct));
        _links      = new(() => links.GetAllAsync(ct));
        _listeners  = new(async () =>
        {
            if (!OperatingSystem.IsLinux()) return string.Empty;
            // -l listening, -u UDP, -n numeric, -p owning process.
            var res = await runner.RunAsync("ss", ["-lunp"], TimeSpan.FromSeconds(5), ct);
            return res.Output ?? string.Empty;
        });
    }

    public Task<IReadOnlyList<DhcpSubnet>> SubnetsAsync() => _subnets.Value;
    public Task<IReadOnlyList<DhcpPool>> PoolsAsync() => _pools.Value;
    public Task<IReadOnlyList<DhcpLease>> LeasesAsync() => _leases.Value;
    public Task<IReadOnlyList<FwInterface>> InterfacesAsync() => _interfaces.Value;
    public Task<IReadOnlyList<ServiceHealth>> UnitsAsync() => _units.Value;
    public Task<IReadOnlyList<InterfaceHealth>> LinksAsync() => _links.Value;
    public Task<string> UdpListenersAsync() => _listeners.Value;

    public async Task<ServiceHealth?> DhcpUnitAsync() =>
        (await UnitsAsync()).FirstOrDefault(u => u.UnitName.Contains("dhcp", StringComparison.OrdinalIgnoreCase));
}

public interface IDhcpDoctorContextFactory
{
    DhcpDoctorContext Create(CancellationToken ct);
}

public sealed class DhcpDoctorContextFactory : IDhcpDoctorContextFactory
{
    private readonly IDhcpAdminService _dhcp;
    private readonly IFirewallService _fw;
    private readonly ISystemServiceHealthService _units;
    private readonly IInterfaceHealthService _links;
    private readonly IProcessRunner _runner;
    private readonly Microsoft.Extensions.Options.IOptions<DiagnosticsOptions> _opts;

    public DhcpDoctorContextFactory(
        IDhcpAdminService dhcp, IFirewallService fw, ISystemServiceHealthService units,
        IInterfaceHealthService links, IProcessRunner runner, Microsoft.Extensions.Options.IOptions<DiagnosticsOptions> opts)
    {
        _dhcp = dhcp; _fw = fw; _units = units; _links = links; _runner = runner; _opts = opts;
    }

    public DhcpDoctorContext Create(CancellationToken ct) =>
        new(_dhcp, _fw, _units, _links, _runner, _opts.Value, ct);
}

public interface IDhcpDoctorCheck : IDoctorCheck<DhcpDoctorContext> { }
public abstract class DhcpDoctorCheckBase : DoctorCheckBase<DhcpDoctorContext>, IDhcpDoctorCheck { }

public static class DhcpRemedies
{
    public static DiagRemedy Subnets(string? hint = null) => new("DHCP subnets", "/Dhcp/Subnets", hint);
    public static DiagRemedy Pools(string? hint = null) => new("DHCP pools", "/Dhcp/Pools", hint);
    public static DiagRemedy Leases(string? hint = null) => new("DHCP leases", "/Dhcp/Leases", hint);
    public static DiagRemedy Service(string? hint = null) => new("Service health", "/Monitoring", hint ?? "systemctl status netfirewall-dhcp");
    public static DiagRemedy FilterRules(string? hint = null) => new("Filter rules", "/Firewall/FilterRules", hint);
}
