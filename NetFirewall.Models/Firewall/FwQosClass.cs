using RepoDb.Attributes;

namespace NetFirewall.Models.Firewall;

public class FwQosClass
{
    [Map("id")]
    public Guid Id { get; set; }

    [Map("qos_config_id")]
    public Guid? QosConfigId { get; set; }

    [Map("name")]
    public string Name { get; set; } = string.Empty;

    [Map("mark_id")]
    public Guid? MarkId { get; set; }

    [Map("guaranteed_mbps")]
    public int GuaranteedMbps { get; set; }

    [Map("ceiling_mbps")]
    public int CeilingMbps { get; set; }

    [Map("priority")]
    public int Priority { get; set; }

    [Map("created_at")]
    public DateTime CreatedAt { get; set; }

    // Navigation properties (not mapped)
    public FwQosConfig? QosConfig { get; set; }
    public FwTrafficMark? Mark { get; set; }
}
