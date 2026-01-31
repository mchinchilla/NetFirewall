using System.Net;
using RepoDb.Attributes;

namespace NetFirewall.Models.Firewall;

public class FwNatRule
{
    [Map("id")]
    public Guid Id { get; set; }

    [Map("type")]
    public string Type { get; set; } = "masquerade"; // masquerade, snat

    [Map("description")]
    public string? Description { get; set; }

    [Map("source_network")]
    public string SourceNetwork { get; set; } = string.Empty; // CIDR notation

    [Map("output_interface_id")]
    public Guid? OutputInterfaceId { get; set; }

    [Map("snat_address")]
    public IPAddress? SnatAddress { get; set; }

    [Map("enabled")]
    public bool Enabled { get; set; } = true;

    [Map("priority")]
    public int Priority { get; set; } = 100;

    [Map("created_at")]
    public DateTime CreatedAt { get; set; }

    // Navigation property (not mapped)
    public FwInterface? OutputInterface { get; set; }
}
