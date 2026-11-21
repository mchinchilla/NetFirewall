using System.Net.NetworkInformation;

namespace NetFirewall.Models.Dhcp;

/// <summary>
/// A device the DHCP server must never answer (dhcp_mac_blocklist, migration 00053). Every
/// packet from it — DISCOVER, REQUEST, RELEASE, INFORM — is dropped in silence, and adding it
/// purges its current lease so it doesn't linger until expiry.
/// </summary>
public sealed class DhcpBlockedMac
{
    public Guid Id { get; set; }
    public PhysicalAddress MacAddress { get; set; } = PhysicalAddress.None;
    public string? Reason { get; set; }
    public DateTime CreatedAt { get; set; }
}
