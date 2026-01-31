using System.Net;
using RepoDb.Attributes;

namespace NetFirewall.Models.Dhcp;

/// <summary>
/// Represents a DHCP subnet/scope configuration.
/// Supports multiple subnets with different configurations.
/// </summary>
[Map("dhcp_subnets")]
public class DhcpSubnet
{
    [Map("id")]
    public Guid Id { get; set; }

    [Map("name")]
    public string Name { get; set; } = string.Empty;

    /// <summary>
    /// Network address in CIDR notation (e.g., "192.168.1.0/24")
    /// </summary>
    [Map("network")]
    public string Network { get; set; } = string.Empty;

    [Map("subnet_mask")]
    public IPAddress? SubnetMask { get; set; }

    [Map("router")]
    public IPAddress? Router { get; set; }

    [Map("broadcast")]
    public IPAddress? Broadcast { get; set; }

    [Map("domain_name")]
    public string? DomainName { get; set; }

    /// <summary>
    /// DNS servers for this subnet
    /// </summary>
    [Map("dns_servers")]
    public IPAddress[]? DnsServers { get; set; }

    /// <summary>
    /// NTP servers for this subnet
    /// </summary>
    [Map("ntp_servers")]
    public IPAddress[]? NtpServers { get; set; }

    /// <summary>
    /// WINS/NetBIOS name servers
    /// </summary>
    [Map("wins_servers")]
    public IPAddress[]? WinsServers { get; set; }

    /// <summary>
    /// Default lease time in seconds
    /// </summary>
    [Map("default_lease_time")]
    public int DefaultLeaseTime { get; set; } = 86400; // 24 hours

    /// <summary>
    /// Maximum lease time in seconds
    /// </summary>
    [Map("max_lease_time")]
    public int MaxLeaseTime { get; set; } = 604800; // 7 days

    /// <summary>
    /// Interface MTU
    /// </summary>
    [Map("interface_mtu")]
    public int? InterfaceMtu { get; set; }

    /// <summary>
    /// TFTP server for PXE boot
    /// </summary>
    [Map("tftp_server")]
    public string? TftpServer { get; set; }

    /// <summary>
    /// Boot filename for PXE
    /// </summary>
    [Map("boot_filename")]
    public string? BootFilename { get; set; }

    /// <summary>
    /// Boot filename for UEFI clients
    /// </summary>
    [Map("boot_filename_uefi")]
    public string? BootFilenameUefi { get; set; }

    /// <summary>
    /// Domain search list for Option 119 (comma-separated domains)
    /// e.g., "example.com,corp.example.com"
    /// </summary>
    [Map("domain_search")]
    public string? DomainSearchList { get; set; }

    /// <summary>
    /// Static routes as JSON array for Option 121 (RFC 3442)
    /// Format: [{"network": "10.0.0.0/8", "gateway": "192.168.1.1"}, ...]
    /// </summary>
    [Map("static_routes")]
    public string? StaticRoutesJson { get; set; }

    /// <summary>
    /// Time offset from UTC in seconds for Option 2
    /// </summary>
    [Map("time_offset")]
    public int? TimeOffset { get; set; }

    /// <summary>
    /// POSIX timezone string for Option 100
    /// e.g., "EST5EDT,M3.2.0,M11.1.0"
    /// </summary>
    [Map("posix_timezone")]
    public string? PosixTimezone { get; set; }

    /// <summary>
    /// Whether this subnet is enabled
    /// </summary>
    [Map("enabled")]
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Network interface this subnet is bound to
    /// </summary>
    [Map("interface_name")]
    public string? InterfaceName { get; set; }

    [Map("created_at")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    [Map("updated_at")]
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;

    // Navigation properties (not mapped)
    public List<DhcpPool>? Pools { get; set; }
}
