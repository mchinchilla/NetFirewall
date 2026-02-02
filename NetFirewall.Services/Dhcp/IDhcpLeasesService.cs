using NetFirewall.Models.Dhcp;
using System.Net;

namespace NetFirewall.Services.Dhcp;

public interface IDhcpLeasesService
{
    // Single lease operations
    Task<IPAddress?> OfferLeaseAsync(string macAddress, IPAddress? rangeStart, IPAddress rangeEnd);
    Task AssignLeaseAsync(string macAddress, IPAddress ipAddress, int leaseTime);

    /// <summary>
    /// Assign a lease with DDNS support.
    /// </summary>
    /// <param name="macAddress">Client MAC address</param>
    /// <param name="ipAddress">IP address to assign</param>
    /// <param name="leaseTime">Lease time in seconds</param>
    /// <param name="hostname">Client hostname for DDNS</param>
    /// <param name="subnetId">Subnet ID for DDNS config lookup</param>
    /// <param name="cancellationToken">Cancellation token</param>
    Task<DdnsUpdateResult?> AssignLeaseWithDdnsAsync(
        string macAddress,
        IPAddress ipAddress,
        int leaseTime,
        string? hostname,
        Guid? subnetId,
        CancellationToken cancellationToken = default);

    Task<bool> CanAssignIpAsync(string macAddress, IPAddress ipAddress);
    Task ReleaseLeaseAsync(string macAddress);

    /// <summary>
    /// Release a lease with DDNS cleanup.
    /// </summary>
    Task<DdnsUpdateResult?> ReleaseLeaseWithDdnsAsync(
        string macAddress,
        Guid? subnetId,
        CancellationToken cancellationToken = default);

    Task MarkIpAsDeclinedAsync(IPAddress ipAddress);

    /// <summary>
    /// Check if an IP is in the declined state (ARP conflict detected).
    /// Declined IPs are temporarily excluded from allocation.
    /// </summary>
    bool IsIpDeclined(IPAddress ipAddress);

    Task<IPAddress?> GetAssignedIpAsync(string macAddress);

    /// <summary>
    /// Get a lease with its FQDN if registered with DDNS.
    /// </summary>
    Task<(DhcpLease? Lease, string? Fqdn)> GetLeaseWithFqdnAsync(
        string macAddress,
        CancellationToken cancellationToken = default);

    // Bulk operations using PostgreSQL COPY protocol (BinaryBulkInsert)
    Task<int> BulkImportReservationsAsync(IEnumerable<DhcpMacReservation> reservations, CancellationToken cancellationToken = default);
    Task<int> BulkImportLeasesAsync(IEnumerable<DhcpLease> leases, CancellationToken cancellationToken = default);

    // Maintenance operations
    Task<int> CleanupExpiredLeasesAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<DhcpLease>> GetAllActiveLeasesAsync(CancellationToken cancellationToken = default);
    Task<IReadOnlyList<DhcpMacReservation>> GetAllReservationsAsync(CancellationToken cancellationToken = default);
}
