using RepoDb.Attributes;

namespace NetFirewall.Models.Vpn;

[Map("wg_peers")]
public class WgPeer
{
    [Map("id")]                    public Guid     Id                  { get; set; }
    [Map("server_id")]             public Guid     ServerId            { get; set; }
    [Map("name")]                  public string   Name                { get; set; } = string.Empty;
    [Map("public_key")]            public string   PublicKey           { get; set; } = string.Empty;
    [Map("preshared_key")]         public string?  PresharedKey        { get; set; }
    [Map("allowed_ips")]           public string[] AllowedIps          { get; set; } = Array.Empty<string>();
    [Map("persistent_keepalive")]  public int?     PersistentKeepalive { get; set; }
    [Map("description")]           public string?  Description         { get; set; }
    [Map("enabled")]               public bool     Enabled             { get; set; } = true;
    [Map("created_at")]            public DateTime CreatedAt           { get; set; }
}

/// <summary>
/// Live status from <c>wg show</c>. Not persisted — built per-request from the
/// daemon endpoint and joined to the peer by public key.
/// </summary>
public sealed record WgPeerLiveStatus(
    string PublicKey,
    string? Endpoint,
    DateTime? LastHandshakeAt,
    long RxBytes,
    long TxBytes);
