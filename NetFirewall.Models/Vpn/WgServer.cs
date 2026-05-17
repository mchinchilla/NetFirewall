using RepoDb.Attributes;

namespace NetFirewall.Models.Vpn;

[Map("wg_servers")]
public class WgServer
{
    [Map("id")]            public Guid     Id           { get; set; }
    [Map("name")]          public string   Name         { get; set; } = "wg0";
    // "server" = accepts inbound peers (ListenPort matters). "client" = initiates
    // a tunnel to a remote wg server (ListenPort ignored, exactly one peer with
    // Endpoint set). Constraint chk_wg_mode enforces these two values in DB.
    [Map("mode")]          public string   Mode         { get; set; } = "server";
    [Map("private_key")]   public string   PrivateKey   { get; set; } = string.Empty;
    [Map("public_key")]    public string   PublicKey    { get; set; } = string.Empty;
    [Map("listen_port")]   public int      ListenPort   { get; set; } = 51820;
    [Map("address_cidr")]  public string   AddressCidr  { get; set; } = "10.10.0.1/24";
    // Client-mode extras. wg-quick honors all three from [Interface]:
    //   DNS = ...    MTU = ...    Table = off
    // null/false means "don't emit" so the wg-quick default applies.
    [Map("dns")]           public string?  Dns          { get; set; }
    [Map("mtu")]           public int?     Mtu          { get; set; }
    [Map("table_off")]     public bool     TableOff     { get; set; }
    [Map("post_up")]       public string?  PostUp       { get; set; }
    [Map("post_down")]     public string?  PostDown     { get; set; }
    [Map("enabled")]       public bool     Enabled      { get; set; } = true;
    [Map("created_at")]    public DateTime CreatedAt    { get; set; }
    [Map("updated_at")]    public DateTime UpdatedAt    { get; set; }
}
