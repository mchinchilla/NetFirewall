using NetFirewall.Web.Models.Dhcp;

namespace NetFirewall.Web.Services;

/// <summary>Builds the on-demand detail panel of a lease row (Leases grid → expand).</summary>
public interface IDhcpLeaseDetailService
{
    Task<LeaseDetailViewModel?> GetAsync(string mac, CancellationToken ct = default);
}
