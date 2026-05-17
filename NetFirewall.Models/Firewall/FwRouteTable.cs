using RepoDb.Attributes;

namespace NetFirewall.Models.Firewall;

[Map("fw_route_tables")]
public class FwRouteTable
{
    [Map("id")]          public Guid Id          { get; set; }
    [Map("table_id")]    public int TableId      { get; set; }   // 200..252
    [Map("table_name")]  public string Name      { get; set; } = string.Empty;
    [Map("description")] public string? Description { get; set; }
    [Map("enabled")]     public bool Enabled     { get; set; } = true;
    [Map("created_at")]  public DateTime CreatedAt { get; set; }
}

[Map("fw_policy_rules")]
public class FwPolicyRule
{
    [Map("id")]          public Guid Id            { get; set; }
    [Map("fwmark")]      public long Fwmark        { get; set; }   // e.g. 256 (0x100)
    [Map("table_name")]  public string TableName   { get; set; } = string.Empty;
    [Map("priority")]    public int? Priority      { get; set; }   // null = kernel-assigned
    [Map("description")] public string? Description { get; set; }
    [Map("enabled")]     public bool Enabled       { get; set; } = true;
    [Map("created_at")]  public DateTime CreatedAt { get; set; }
}
