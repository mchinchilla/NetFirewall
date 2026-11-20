using NetFirewall.Models.Dhcp;

namespace NetFirewall.Web.Models.Dhcp;

/// <summary>
/// One subnet plus what the Subnets grid shows next to it: the interface it serves and how many
/// pools / exclusions hang off it (the counts on the row's Pools / Exclusions links).
/// </summary>
public sealed record SubnetOverview(DhcpSubnet Subnet, string? InterfaceName, string? InterfaceType, int PoolCount, int ExclusionCount);

/// <summary>Expanded row of the Subnets grid: the scope's options plus its pools and exclusions.</summary>
public sealed class SubnetDetailViewModel
{
    public required DhcpSubnet Subnet { get; init; }
    public string? InterfaceName { get; init; }
    public IReadOnlyList<DhcpPool> Pools { get; init; } = [];
    public IReadOnlyList<DhcpExclusion> Exclusions { get; init; } = [];
}
