using RepoDb.Attributes;

namespace NetFirewall.Models.Firewall;

public class FwFilterRule
{
    [Map("id")]
    public Guid Id { get; set; }

    [Map("chain")]
    public string Chain { get; set; } = "input"; // input, forward, output

    [Map("description")]
    public string? Description { get; set; }

    [Map("action")]
    public string Action { get; set; } = "accept"; // accept, drop, reject, log

    [Map("protocol")]
    public string? Protocol { get; set; } // tcp, udp, icmp, null = any

    [Map("interface_in_id")]
    public Guid? InterfaceInId { get; set; }

    [Map("interface_out_id")]
    public Guid? InterfaceOutId { get; set; }

    [Map("source_addresses")]
    public string[]? SourceAddresses { get; set; }

    [Map("destination_addresses")]
    public string[]? DestinationAddresses { get; set; }

    [Map("destination_ports")]
    public string[]? DestinationPorts { get; set; }

    [Map("connection_state")]
    public string[]? ConnectionState { get; set; } // new, established, related

    [Map("rate_limit")]
    public string? RateLimit { get; set; }

    [Map("log_prefix")]
    public string? LogPrefix { get; set; }

    [Map("enabled")]
    public bool Enabled { get; set; } = true;

    [Map("priority")]
    public int Priority { get; set; } = 100;

    [Map("created_at")]
    public DateTime CreatedAt { get; set; }

    // Navigation properties (not mapped)
    public FwInterface? InterfaceIn { get; set; }
    public FwInterface? InterfaceOut { get; set; }
}
