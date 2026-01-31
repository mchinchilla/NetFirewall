using System.Net;
using RepoDb.Attributes;

namespace NetFirewall.Models.Firewall;

public class FwPortForward
{
    [Map("id")]
    public Guid Id { get; set; }

    [Map("description")]
    public string? Description { get; set; }

    [Map("protocol")]
    public string Protocol { get; set; } = "tcp"; // tcp, udp, tcp/udp

    [Map("interface_id")]
    public Guid? InterfaceId { get; set; }

    [Map("source_addresses")]
    public string[]? SourceAddresses { get; set; }

    [Map("external_port_start")]
    public int ExternalPortStart { get; set; }

    [Map("external_port_end")]
    public int? ExternalPortEnd { get; set; }

    [Map("internal_ip")]
    public IPAddress InternalIp { get; set; } = IPAddress.None;

    [Map("internal_port")]
    public int InternalPort { get; set; }

    [Map("enabled")]
    public bool Enabled { get; set; } = true;

    [Map("priority")]
    public int Priority { get; set; } = 100;

    [Map("created_at")]
    public DateTime CreatedAt { get; set; }

    // Navigation property (not mapped)
    public FwInterface? Interface { get; set; }
}
