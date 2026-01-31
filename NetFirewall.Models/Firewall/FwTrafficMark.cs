using RepoDb.Attributes;

namespace NetFirewall.Models.Firewall;

public class FwTrafficMark
{
    [Map("id")]
    public Guid Id { get; set; }

    [Map("name")]
    public string Name { get; set; } = string.Empty;

    [Map("mark_value")]
    public int MarkValue { get; set; }

    [Map("description")]
    public string? Description { get; set; }

    [Map("route_table")]
    public string? RouteTable { get; set; }

    [Map("created_at")]
    public DateTime CreatedAt { get; set; }
}
