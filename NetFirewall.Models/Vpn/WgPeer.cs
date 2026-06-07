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
    // "host:port" of the remote side. REQUIRED when the parent server is in
    // 'client' mode (this peer represents the remote wg server we connect to).
    // Optional for inbound peers in 'server' mode — some site-to-site configs
    // also set Endpoint there for symmetric keepalive.
    [Map("endpoint")]              public string?  Endpoint            { get; set; }
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
