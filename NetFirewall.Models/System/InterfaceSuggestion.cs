using System.Net;

namespace NetFirewall.Models.System;

public class InterfaceSuggestion
{
    public string Name { get; set; } = string.Empty;
    public string SuggestedType { get; set; } = string.Empty;   // WAN, LAN, VPN
    public string SuggestedRole { get; set; } = string.Empty;   // primary_wan, secondary_wan, local_network
    public int Confidence { get; set; }                          // 0-100%
    public string Reason { get; set; } = string.Empty;
    public string? MacAddress { get; set; }
    public IPAddress? CurrentIp { get; set; }
    public string? CurrentSubnet { get; set; }
    public IPAddress? CurrentGateway { get; set; }
    public bool IsUp { get; set; }
    public bool IsVirtual { get; set; }
    public int? Mtu { get; set; }

    /// <summary>
    /// The DECLARED addressing mode read from the system network config
    /// ("dhcp" / "static" / "disabled"), or null if it couldn't be determined.
    /// Populated by the daemon's discovery (it can read /etc/network/interfaces,
    /// netplan, nmcli). The wizard prefers this over its WAN/gateway heuristic.
    /// </summary>
    public string? AddressingMode { get; set; }
}
