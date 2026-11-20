using NetFirewall.Web.Models.Dhcp;

namespace NetFirewall.Web.Services;

/// <summary>Rows and row detail of the DHCP Subnets grid.</summary>
public interface IDhcpSubnetOverviewService
{
    /// <summary>Every subnet with its interface name/type and pool/exclusion counts.</summary>
    Task<IReadOnlyList<SubnetOverview>> GetAllAsync(CancellationToken ct = default);

    /// <summary>One subnet's options, pools and exclusions; null when the subnet is gone.</summary>
    Task<SubnetDetailViewModel?> GetDetailAsync(Guid id, CancellationToken ct = default);
}
