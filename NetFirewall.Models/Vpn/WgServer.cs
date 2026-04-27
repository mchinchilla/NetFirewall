using RepoDb.Attributes;

namespace NetFirewall.Models.Vpn;

[Map("wg_servers")]
public class WgServer
{
    [Map("id")]            public Guid     Id           { get; set; }
    [Map("name")]          public string   Name         { get; set; } = "wg0";
    [Map("private_key")]   public string   PrivateKey   { get; set; } = string.Empty;
    [Map("public_key")]    public string   PublicKey    { get; set; } = string.Empty;
    [Map("listen_port")]   public int      ListenPort   { get; set; } = 51820;
    [Map("address_cidr")]  public string   AddressCidr  { get; set; } = "10.10.0.1/24";
    [Map("post_up")]       public string?  PostUp       { get; set; }
    [Map("post_down")]     public string?  PostDown     { get; set; }
    [Map("enabled")]       public bool     Enabled      { get; set; } = true;
    [Map("created_at")]    public DateTime CreatedAt    { get; set; }
    [Map("updated_at")]    public DateTime UpdatedAt    { get; set; }
}
