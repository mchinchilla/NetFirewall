namespace NetFirewall.Models.WanMonitor;

/// <summary>
/// Per-interface health config. The daemon's WanHealthMonitorService reads
/// these rows once at startup (and on Reload). One row per WAN interface;
/// priority resolves ties when multiple WANs are healthy.
/// </summary>
public sealed class WanHealthConfig
{
    public Guid Id                  { get; set; }
    public Guid InterfaceId         { get; set; }
    /// <summary>Lower = preferred. priority=1 is the default WAN.</summary>
    public int Priority             { get; set; }
    /// <summary>IPs to ping. Empty = use the interface's gateway.</summary>
    public string[] MonitorTargets  { get; set; } = Array.Empty<string>();
    /// <summary>
    /// fwmark to set on probe packets (ping -m). Forces the kernel to route
    /// the probe via the policy rule that matches this mark, which in turn
    /// pins it to the correct WAN. Null = legacy -I behavior; only reliable
    /// when probing L2-adjacent targets like the gateway.
    /// </summary>
    public long? ProbeFwmark        { get; set; }
    public int FailoverThreshold    { get; set; } = 3;
    public int RecoveryThreshold    { get; set; } = 5;
    public bool Enabled             { get; set; } = true;
    public DateTime CreatedAt       { get; set; }
    public DateTime UpdatedAt       { get; set; }

    // Denormalized for convenience — populated by the loader from fw_interfaces.
    public string InterfaceName     { get; set; } = string.Empty;
}

/// <summary>
/// Current health state — one row per interface, UPSERTed on every probe cycle.
/// <c>IsUp</c> is the cooked verdict (true until consecutive_failures crosses
/// the threshold). Raw ping results live only in <c>wan_health_events</c>
/// when they cause a transition.
/// </summary>
public sealed class WanHealthState
{
    public Guid InterfaceId              { get; set; }
    public bool IsUp                     { get; set; } = true;
    public int ConsecutiveFailures       { get; set; }
    public int ConsecutiveSuccesses      { get; set; }
    public DateTime LastCheckAt          { get; set; }
    public DateTime LastTransitionAt     { get; set; }
    public double? LastRttMs             { get; set; }
    public string? LastTarget            { get; set; }
    public string? LastError             { get; set; }

    // Denormalized for the dashboard.
    public string InterfaceName          { get; set; } = string.Empty;
    public string Role                   { get; set; } = string.Empty;
}

/// <summary>
/// Singleton control row: which WAN is currently the active default route, and
/// whether an operator has pinned one via a sticky manual override. Read by the
/// dashboard (to show + let the operator swap the active WAN) and by the monitor
/// (to honor the override). See migration 00035.
/// </summary>
public sealed class WanFailoverControl
{
    /// <summary>Manually-pinned interface, or null for auto (priority-based) selection.</summary>
    public Guid? OverrideInterfaceId { get; set; }
    public string? OverrideSetBy     { get; set; }
    public DateTime? OverrideSetAt   { get; set; }

    /// <summary>The interface the monitor last made the default route (UI cache).</summary>
    public Guid? ActiveInterfaceId   { get; set; }
    public DateTime? ActiveSince     { get; set; }

    // Denormalized for the UI — populated by the loader from fw_interfaces.
    public string? OverrideInterfaceName { get; set; }
    public string? ActiveInterfaceName   { get; set; }
}

/// <summary>
/// Transition event. Only written when something changes (up↔down, or this
/// interface becomes/stops being the active default route).
/// </summary>
public sealed class WanHealthEvent
{
    public long Id                  { get; set; }
    public DateTime OccurredAt      { get; set; }
    public Guid InterfaceId         { get; set; }
    public string EventType         { get; set; } = string.Empty;  // up | down | failover | demoted
    public string? Detail           { get; set; }                  // JSON string

    // Denormalized.
    public string InterfaceName     { get; set; } = string.Empty;
}
