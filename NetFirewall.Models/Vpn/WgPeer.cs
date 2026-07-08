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
    // "host:port" of the remote side. REQUIRED for role 'upstream' (we dial it);
    // optional for 'site' (symmetric keepalive); unused for 'client' peers.
    [Map("endpoint")]              public string?  Endpoint            { get; set; }
    // What this peer IS (migration 00036, CHECK chk_wg_peer_role):
    //   'upstream' — remote wg server we dial out to (health-monitored)
    //   'client'   — inbound road-warrior; may be offline (never monitored)
    //   'site'     — site-to-site link (health-monitored)
    // This — not the server-level mode — decides monitoring, NAT/forward
    // generation, and which UI section/form the peer lives in.
    [Map("role")]                  public string   Role                { get; set; } = "client";
    // Per-peer routing intent (server mode), drives generated NAT/forward + the
    // exported client config's AllowedIPs. 'full' = LAN+internet, 'split' = LAN only,
    // 'restricted' = only AllowedSubnets, 'site' = site-to-site (AllowedSubnets are
    // the remote LAN). DB CHECK chk_wg_peer_route_mode (migration 00032).
    [Map("route_mode")]            public string   RouteMode           { get; set; } = "full";
    // Target subnets for split/restricted/site modes.
    [Map("allowed_subnets")]       public string[] AllowedSubnets      { get; set; } = Array.Empty<string>();
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
