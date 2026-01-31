using RepoDb.Attributes;

namespace NetFirewall.Models.Firewall;

public class FwMangleRule
{
    [Map("id")]
    public Guid Id { get; set; }

    [Map("chain")]
    public string Chain { get; set; } = "prerouting"; // prerouting, postrouting

    [Map("description")]
    public string? Description { get; set; }

    [Map("mark_id")]
    public Guid? MarkId { get; set; }

    [Map("protocol")]
    public string? Protocol { get; set; }

    [Map("source_addresses")]
    public string[]? SourceAddresses { get; set; }

    [Map("destination_addresses")]
    public string[]? DestinationAddresses { get; set; }

    [Map("destination_ports")]
    public string[]? DestinationPorts { get; set; }

    [Map("enabled")]
    public bool Enabled { get; set; } = true;

    [Map("priority")]
    public int Priority { get; set; } = 100;

    [Map("created_at")]
    public DateTime CreatedAt { get; set; }

    // Navigation property (not mapped)
    public FwTrafficMark? Mark { get; set; }
}
