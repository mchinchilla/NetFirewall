using System.Net;
using NetFirewall.Models.Dhcp;
using NetFirewall.Models.Firewall;

namespace NetFirewall.Services.Dhcp;

/// <summary>
/// Service for managing DHCP subnets, pools, and subnet selection.
/// </summary>
public interface IDhcpSubnetService
{
    /// <summary>
    /// Find the appropriate subnet for a DHCP request.
    /// Uses giaddr (relay agent) if present, otherwise uses the receiving interface.
    /// </summary>
    Task<DhcpSubnet?> FindSubnetForRequestAsync(DhcpRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Find subnet by network address (CIDR match).
    /// </summary>
    Task<DhcpSubnet?> FindSubnetByNetworkAsync(IPAddress ipAddress, CancellationToken cancellationToken = default);

    /// <summary>
    /// Find subnet by interface name.
    /// </summary>
    Task<DhcpSubnet?> FindSubnetByInterfaceAsync(string interfaceName, CancellationToken cancellationToken = default);

    /// <summary>
    /// Get all enabled subnets.
    /// </summary>
    Task<IReadOnlyList<DhcpSubnet>> GetAllSubnetsAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Get unique network interfaces from enabled subnets.
    /// Used by DhcpWorker to determine which interfaces to listen on.
    /// </summary>
    Task<IReadOnlyList<FwInterface>> GetEnabledInterfacesAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Get subnet by ID with its pools.
    /// </summary>
    Task<DhcpSubnet?> GetSubnetWithPoolsAsync(Guid subnetId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Get all pools for a subnet.
    /// </summary>
    Task<IReadOnlyList<DhcpPool>> GetPoolsForSubnetAsync(Guid subnetId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Find an available IP in the subnet's pools.
    /// </summary>
    Task<(IPAddress? Ip, DhcpPool? Pool)> FindAvailableIpInSubnetAsync(
        DhcpSubnet subnet,
        string macAddress,
        DhcpRequest request,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Check if a client matches any defined class.
    /// </summary>
    Task<DhcpClass?> MatchClientClassAsync(DhcpRequest request, CancellationToken cancellationToken = default);

    /// <summary>
    /// Get exclusions for a subnet.
    /// </summary>
    Task<IReadOnlyList<DhcpExclusion>> GetExclusionsForSubnetAsync(Guid subnetId, CancellationToken cancellationToken = default);

    // CRUD operations
    Task<DhcpSubnet> CreateSubnetAsync(DhcpSubnet subnet, CancellationToken cancellationToken = default);
    Task<DhcpSubnet> UpdateSubnetAsync(DhcpSubnet subnet, CancellationToken cancellationToken = default);
    Task<bool> DeleteSubnetAsync(Guid subnetId, CancellationToken cancellationToken = default);

    Task<DhcpPool> CreatePoolAsync(DhcpPool pool, CancellationToken cancellationToken = default);
    Task<bool> DeletePoolAsync(Guid poolId, CancellationToken cancellationToken = default);
}
