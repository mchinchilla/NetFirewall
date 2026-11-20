using NetFirewall.Services.Dhcp;
using NetFirewall.Services.Firewall;
using NetFirewall.Web.Models.Dhcp;

namespace NetFirewall.Web.Services;

/// <summary>
/// Composes <see cref="IDhcpAdminService"/> (subnets, pools, exclusions) with
/// <see cref="IFirewallService"/> (interface names). <c>dhcp_subnets</c> only stores the
/// interface id, so the name is joined here, in memory, once per grid load.
/// </summary>
public sealed class DhcpSubnetOverviewService(IDhcpAdminService admin, IFirewallService firewall) : IDhcpSubnetOverviewService
{
    public async Task<IReadOnlyList<SubnetOverview>> GetAllAsync(CancellationToken ct = default)
    {
        var subnets = await admin.GetSubnetsAsync(ct);
        var pools = await admin.GetPoolsAsync(null, ct);
        var exclusions = await admin.GetExclusionsAsync(null, ct);
        var ifaces = (await firewall.GetInterfacesAsync(ct)).ToDictionary(i => i.Id);

        var poolCounts = pools.Where(p => p.SubnetId.HasValue)
            .GroupBy(p => p.SubnetId!.Value)
            .ToDictionary(g => g.Key, g => g.Count());
        var exclCounts = exclusions.GroupBy(e => e.SubnetId).ToDictionary(g => g.Key, g => g.Count());

        return subnets.Select(s =>
        {
            var iface = s.InterfaceId is { } iid && ifaces.TryGetValue(iid, out var i) ? i : null;
            return new SubnetOverview(s, iface?.Name, iface?.Type,
                poolCounts.GetValueOrDefault(s.Id), exclCounts.GetValueOrDefault(s.Id));
        }).ToArray();
    }

    public async Task<SubnetDetailViewModel?> GetDetailAsync(Guid id, CancellationToken ct = default)
    {
        var subnet = await admin.GetSubnetByIdAsync(id, ct);
        if (subnet is null) return null;

        var iface = subnet.InterfaceId is { } iid ? await firewall.GetInterfaceByIdAsync(iid, ct) : null;
        var pools = await admin.GetPoolsAsync(id, ct);
        var exclusions = await admin.GetExclusionsAsync(id, ct);

        return new SubnetDetailViewModel
        {
            Subnet = subnet,
            InterfaceName = iface?.Name,
            Pools = pools,
            Exclusions = exclusions,
        };
    }
}
