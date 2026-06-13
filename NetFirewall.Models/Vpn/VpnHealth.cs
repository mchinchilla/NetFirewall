namespace NetFirewall.Models.Vpn;

/// <summary>
/// Current health state for one WireGuard peer — one row per (server, public key),
/// UPSERTed every probe cycle by the daemon's VpnHealthMonitorService. <c>IsUp</c>
/// is the cooked verdict (stays true until consecutive_failures crosses the
/// threshold). Mirrors <c>WanHealthState</c>.
/// </summary>
public sealed class VpnHealthState
{
    public Guid ServerId               { get; set; }
    public string PublicKey            { get; set; } = string.Empty;
    public bool IsUp                   { get; set; } = true;
    public int ConsecutiveFailures     { get; set; }
    public int ConsecutiveSuccesses    { get; set; }
    public DateTime LastCheckAt        { get; set; }
    public DateTime LastTransitionAt   { get; set; }
    public DateTime? LastHandshakeAt   { get; set; }
    public string? LastEndpoint        { get; set; }

    // Denormalized for the dashboard — populated from wg_peers / wg_servers.
    public string PeerName             { get; set; } = string.Empty;
    public string ServerName           { get; set; } = string.Empty;
}

/// <summary>
/// A peer up↔down transition. Only written when the cooked verdict flips, so the
/// dashboard timeline and notifications fire once per real change. Mirrors
/// <c>WanHealthEvent</c>.
/// </summary>
public sealed class VpnHealthEvent
{
    public long Id              { get; set; }
    public DateTime OccurredAt  { get; set; }
    public Guid ServerId        { get; set; }
    public string PublicKey     { get; set; } = string.Empty;
    public string EventType     { get; set; } = string.Empty;  // up | down
    public string? Detail       { get; set; }                  // JSON string

    // Denormalized.
    public string PeerName      { get; set; } = string.Empty;
    public string ServerName    { get; set; } = string.Empty;
}

/// <summary>
/// An active UI alert (banner feed). Raised by the monitor on a down transition,
/// resolved on recovery. The Web's notification banner shows rows with
/// <c>ResolvedAt == null</c>. Generic by design so other subsystems can reuse it.
/// </summary>
public sealed class SystemAlert
{
    public long Id              { get; set; }
    public string Source        { get; set; } = string.Empty;  // e.g. "vpn"
    public string Severity      { get; set; } = "danger";       // danger | warning | info
    public string DedupeKey     { get; set; } = string.Empty;
    public string Title         { get; set; } = string.Empty;
    public string? Body         { get; set; }
    public DateTime RaisedAt    { get; set; }
    public DateTime? ResolvedAt { get; set; }
}
