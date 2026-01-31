using System.Net;
using RepoDb.Attributes;

namespace NetFirewall.Models.Dhcp;

/// <summary>
/// Represents an IP address pool within a DHCP subnet.
/// A subnet can have multiple pools with different configurations.
/// </summary>
[Map("dhcp_pools")]
public class DhcpPool
{
    [Map("id")]
    public Guid Id { get; set; }

    [Map("subnet_id")]
    public Guid? SubnetId { get; set; }

    [Map("name")]
    public string? Name { get; set; }

    /// <summary>
    /// Start of IP range
    /// </summary>
    [Map("range_start")]
    public IPAddress RangeStart { get; set; } = null!;

    /// <summary>
    /// End of IP range
    /// </summary>
    [Map("range_end")]
    public IPAddress RangeEnd { get; set; } = null!;

    /// <summary>
    /// Allow unknown/unregistered clients
    /// </summary>
    [Map("allow_unknown_clients")]
    public bool AllowUnknownClients { get; set; } = true;

    /// <summary>
    /// Deny BOOTP clients (only DHCP)
    /// </summary>
    [Map("deny_bootp")]
    public bool DenyBootp { get; set; } = false;

    /// <summary>
    /// Only allow known/registered clients
    /// </summary>
    [Map("known_clients_only")]
    public bool KnownClientsOnly { get; set; } = false;

    /// <summary>
    /// Pool priority (lower = higher priority)
    /// </summary>
    [Map("priority")]
    public int Priority { get; set; } = 100;

    [Map("enabled")]
    public bool Enabled { get; set; } = true;

    [Map("created_at")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    // Navigation
    public DhcpSubnet? Subnet { get; set; }
}

/// <summary>
/// Represents an IP address exclusion within a pool.
/// </summary>
[Map("dhcp_exclusions")]
public class DhcpExclusion
{
    [Map("id")]
    public Guid Id { get; set; }

    [Map("subnet_id")]
    public Guid SubnetId { get; set; }

    [Map("ip_start")]
    public IPAddress IpStart { get; set; } = null!;

    [Map("ip_end")]
    public IPAddress? IpEnd { get; set; }

    [Map("reason")]
    public string? Reason { get; set; }

    [Map("created_at")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
