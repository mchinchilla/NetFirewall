using System.Net;
using NetFirewall.Models.Dhcp;

namespace NetFirewall.Services.Dhcp;

/// <summary>
/// Administration service for DHCP server - used by the web UI.
/// </summary>
public interface IDhcpAdminService
{
    // Subnet/Scope operations
    Task<IReadOnlyList<DhcpSubnet>> GetSubnetsAsync(CancellationToken ct = default);
    Task<DhcpSubnet?> GetSubnetByIdAsync(Guid id, CancellationToken ct = default);
    Task<DhcpSubnet> CreateSubnetAsync(DhcpSubnet subnet, CancellationToken ct = default);
    Task<DhcpSubnet> UpdateSubnetAsync(DhcpSubnet subnet, CancellationToken ct = default);
    Task<bool> DeleteSubnetAsync(Guid id, CancellationToken ct = default);

    // Pool operations
    Task<IReadOnlyList<DhcpPool>> GetPoolsAsync(Guid? subnetId = null, CancellationToken ct = default);
    Task<DhcpPool> CreatePoolAsync(DhcpPool pool, CancellationToken ct = default);
    Task<DhcpPool> UpdatePoolAsync(DhcpPool pool, CancellationToken ct = default);
    Task<bool> DeletePoolAsync(Guid id, CancellationToken ct = default);

    // Lease operations
    Task<IReadOnlyList<DhcpLease>> GetActiveLeasesAsync(CancellationToken ct = default);
    Task<IReadOnlyList<DhcpLease>> GetAllLeasesAsync(bool includeExpired = false, CancellationToken ct = default);
    Task<DhcpLease?> GetLeaseByMacAsync(string macAddress, CancellationToken ct = default);
    Task<bool> ReleaseLeaseAsync(Guid leaseId, CancellationToken ct = default);
    Task<int> CleanupExpiredLeasesAsync(CancellationToken ct = default);

    // Reservation operations
    Task<IReadOnlyList<DhcpMacReservation>> GetReservationsAsync(CancellationToken ct = default);
    Task<DhcpMacReservation?> GetReservationByIdAsync(Guid id, CancellationToken ct = default);
    Task<DhcpMacReservation> CreateReservationAsync(DhcpMacReservation reservation, CancellationToken ct = default);
    Task<DhcpMacReservation> UpdateReservationAsync(DhcpMacReservation reservation, CancellationToken ct = default);
    Task<bool> DeleteReservationAsync(Guid id, CancellationToken ct = default);

    // Statistics
    Task<DhcpStats> GetStatsAsync(CancellationToken ct = default);

    // Failover status
    Task<DhcpFailoverStatus?> GetFailoverStatusAsync(CancellationToken ct = default);

    // DDNS Config
    Task<IReadOnlyList<DdnsConfig>> GetDdnsConfigsAsync(CancellationToken ct = default);
    Task<DdnsConfig> CreateDdnsConfigAsync(DdnsConfig config, CancellationToken ct = default);
    Task<DdnsConfig> UpdateDdnsConfigAsync(DdnsConfig config, CancellationToken ct = default);
    Task<bool> DeleteDdnsConfigAsync(Guid id, CancellationToken ct = default);
}

/// <summary>
/// DHCP server statistics.
/// </summary>
public class DhcpStats
{
    public int TotalSubnets { get; set; }
    public int ActiveSubnets { get; set; }
    public int TotalLeases { get; set; }
    public int ActiveLeases { get; set; }
    public int TotalReservations { get; set; }
    public int TotalPoolSize { get; set; }
    public int AvailableIps { get; set; }
    public double UtilizationPercent => TotalPoolSize > 0 ? (double)ActiveLeases / TotalPoolSize * 100 : 0;
}

/// <summary>
/// DHCP failover status for UI display.
/// </summary>
public class DhcpFailoverStatus
{
    public string LocalState { get; set; } = "Unknown";
    public string PeerState { get; set; } = "Unknown";
    public string Role { get; set; } = "Unknown";
    public string PeerAddress { get; set; } = "";
    public DateTime? LastContact { get; set; }
    public bool IsHealthy { get; set; }
}
