using System.Net;
using RepoDb.Attributes;

namespace NetFirewall.Models.Firewall;

public class FwStaticRoute
{
    [Map("id")]
    public Guid Id { get; set; }

    [Map("interface_id")]
    public Guid InterfaceId { get; set; }

    [Map("destination")]
    public string Destination { get; set; } = string.Empty; // CIDR: 10.0.0.0/8

    [Map("gateway")]
    public IPAddress? Gateway { get; set; }

    [Map("metric")]
    public int Metric { get; set; } = 100;

    [Map("description")]
    public string? Description { get; set; }

    [Map("enabled")]
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Named route table this route lives in. NULL = goes to <c>main</c>.
    /// Set when the route is part of policy routing (e.g., default route in
    /// table <c>wan1</c> matched by an <c>ip rule fwmark 0x100</c>).
    /// </summary>
    [Map("table_id")]
    public Guid? TableId { get; set; }

    [Map("created_at")]
    public DateTime CreatedAt { get; set; }
}
