using NetFirewall.Models.Dhcp;

namespace NetFirewall.Web.Models.Dhcp;

/// <summary>Expanded row of the Leases grid: the lease plus what the rest of DHCP knows about that MAC.</summary>
public sealed class LeaseDetailViewModel
{
    public required DhcpLease Lease { get; init; }
    public required string Mac { get; init; }
    public DhcpMacReservation? Reservation { get; init; }
    public DhcpSubnet? Subnet { get; init; }
    public DateTime NowUtc { get; init; } = DateTime.UtcNow;
}
