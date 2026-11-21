using System.Net;

namespace NetFirewall.Models.Dhcp;

/// <summary>
/// A DHCP relay agent (giaddr) the server knows about (dhcp_relay_agents, migration 00007).
/// Once at least one relay is marked trusted, relayed packets are only answered when their
/// giaddr is a trusted relay; a row marked untrusted is always refused. With no trusted row
/// the server behaves as before (every relay answered). See <see cref="DhcpRelayPolicy"/>.
/// </summary>
public sealed class DhcpRelayAgent
{
    public Guid Id { get; set; }
    public IPAddress IpAddress { get; set; } = IPAddress.Any;
    public string? Description { get; set; }
    public bool Trusted { get; set; } = true;
    public DateTime CreatedAt { get; set; }
}
