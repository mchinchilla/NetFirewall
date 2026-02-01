using System.Net;
using RepoDb.Attributes;

namespace NetFirewall.Models.Firewall;

public class FwInterface
{
    [Map("id")]
    public Guid Id { get; set; }

    [Map("name")]
    public string Name { get; set; } = string.Empty;

    [Map("type")]
    public string Type { get; set; } = string.Empty; // WAN, LAN, VPN

    [Map("role")]
    public string? Role { get; set; } // primary_wan, secondary_wan, local_network

    [Map("ip_address")]
    public IPAddress? IpAddress { get; set; }

    [Map("subnet_mask")]
    public IPAddress? SubnetMask { get; set; }

    [Map("gateway")]
    public IPAddress? Gateway { get; set; }

    [Map("dns_servers")]
    public IPAddress[]? DnsServers { get; set; }

    [Map("mtu")]
    public int? Mtu { get; set; }

    [Map("vlan_id")]
    public int? VlanId { get; set; }

    [Map("vlan_parent")]
    public string? VlanParent { get; set; }

    [Map("addressing_mode")]
    public string AddressingMode { get; set; } = "static"; // static, dhcp, disabled

    [Map("metric")]
    public int? Metric { get; set; }

    [Map("mac_address")]
    public string? MacAddress { get; set; }

    [Map("description")]
    public string? Description { get; set; }

    [Map("auto_start")]
    public bool AutoStart { get; set; } = true;

    [Map("enabled")]
    public bool Enabled { get; set; } = true;

    [Map("created_at")]
    public DateTime CreatedAt { get; set; }

    [Map("updated_at")]
    public DateTime UpdatedAt { get; set; }
}
