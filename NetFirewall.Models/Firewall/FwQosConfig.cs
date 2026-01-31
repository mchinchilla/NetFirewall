using RepoDb.Attributes;

namespace NetFirewall.Models.Firewall;

public class FwQosConfig
{
    [Map("id")]
    public Guid Id { get; set; }

    [Map("interface_id")]
    public Guid? InterfaceId { get; set; }

    [Map("enabled")]
    public bool Enabled { get; set; } = true;

    [Map("total_bandwidth_mbps")]
    public int TotalBandwidthMbps { get; set; }

    [Map("created_at")]
    public DateTime CreatedAt { get; set; }

    // Navigation properties (not mapped)
    public FwInterface? Interface { get; set; }
    public List<FwQosClass>? Classes { get; set; }
}
