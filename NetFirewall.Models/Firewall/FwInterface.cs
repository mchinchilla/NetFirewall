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

    [Map("enabled")]
    public bool Enabled { get; set; } = true;

    [Map("created_at")]
    public DateTime CreatedAt { get; set; }

    [Map("updated_at")]
    public DateTime UpdatedAt { get; set; }
}
