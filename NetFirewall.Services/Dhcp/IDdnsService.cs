using System.Net;
using NetFirewall.Models.Dhcp;

namespace NetFirewall.Services.Dhcp;

/// <summary>
/// Service for Dynamic DNS (RFC 2136) updates.
/// </summary>
public interface IDdnsService
{
    /// <summary>
    /// Register a forward (A) record for a lease.
    /// </summary>
    /// <param name="hostname">Client hostname (without domain)</param>
    /// <param name="ipAddress">Assigned IP address</param>
    /// <param name="config">DDNS configuration</param>
    /// <param name="macAddress">Client MAC for DHCID generation</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if update succeeded</returns>
    Task<bool> AddForwardRecordAsync(
        string hostname,
        IPAddress ipAddress,
        DdnsConfig config,
        string macAddress,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Register a reverse (PTR) record for a lease.
    /// </summary>
    /// <param name="ipAddress">Assigned IP address</param>
    /// <param name="fqdn">Fully qualified domain name</param>
    /// <param name="config">DDNS configuration</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>True if update succeeded</returns>
    Task<bool> AddReverseRecordAsync(
        IPAddress ipAddress,
        string fqdn,
        DdnsConfig config,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Remove forward (A) record when lease expires/releases.
    /// </summary>
    Task<bool> RemoveForwardRecordAsync(
        string hostname,
        IPAddress ipAddress,
        DdnsConfig config,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Remove reverse (PTR) record when lease expires/releases.
    /// </summary>
    Task<bool> RemoveReverseRecordAsync(
        IPAddress ipAddress,
        DdnsConfig config,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Perform full DNS update for a lease (both A and PTR).
    /// </summary>
    /// <param name="hostname">Client hostname</param>
    /// <param name="ipAddress">Assigned IP address</param>
    /// <param name="macAddress">Client MAC address</param>
    /// <param name="config">DDNS configuration</param>
    /// <param name="cancellationToken">Cancellation token</param>
    /// <returns>Result indicating success/failure for each record type</returns>
    Task<DdnsUpdateResult> UpdateLeaseRecordsAsync(
        string hostname,
        IPAddress ipAddress,
        string macAddress,
        DdnsConfig config,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Remove all DNS records for a lease.
    /// </summary>
    Task<DdnsUpdateResult> RemoveLeaseRecordsAsync(
        string hostname,
        IPAddress ipAddress,
        DdnsConfig config,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Get DDNS configuration for a subnet.
    /// </summary>
    Task<DdnsConfig?> GetConfigForSubnetAsync(
        Guid? subnetId,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Result of a DDNS update operation.
/// </summary>
public class DdnsUpdateResult
{
    public bool ForwardSuccess { get; set; }
    public bool ReverseSuccess { get; set; }
    public string? ForwardError { get; set; }
    public string? ReverseError { get; set; }
    public string? Fqdn { get; set; }

    public bool Success => ForwardSuccess && ReverseSuccess;

    public static DdnsUpdateResult Succeeded(string fqdn) => new()
    {
        ForwardSuccess = true,
        ReverseSuccess = true,
        Fqdn = fqdn
    };

    public static DdnsUpdateResult Failed(string forwardError, string reverseError) => new()
    {
        ForwardSuccess = false,
        ReverseSuccess = false,
        ForwardError = forwardError,
        ReverseError = reverseError
    };

    public static DdnsUpdateResult Disabled() => new()
    {
        ForwardSuccess = true,
        ReverseSuccess = true,
        Fqdn = null
    };
}
