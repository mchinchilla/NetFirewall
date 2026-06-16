using NetFirewall.Models.WanMonitor;

namespace NetFirewall.Web.Models.Network;

/// <summary>
/// Single, shared model for every WAN-health surface in the UI — the failover
/// page panel, the Monitoring "WAN interfaces" pod, and the Home dashboard card.
/// The data is identical across all three (it all comes from the same daemon
/// <c>GetWanHealthAsync</c> DTO, with a DB fallback); what differs is only how
/// much is shown and whether controls are interactive. Those differences are
/// presentation flags on this model, not separate view models / partials.
///
/// Built once by <see cref="NetFirewall.Services.WanMonitor.IWanHealthCardBuilder"/>
/// so the three controllers stop duplicating the daemon→DTO→VM mapping.
/// </summary>
public sealed class WanHealthCardViewModel
{
    public IReadOnlyList<WanHealthCardRow> Wans { get; init; } = Array.Empty<WanHealthCardRow>();
    public IReadOnlyList<WanHealthEvent> RecentEvents { get; init; } = Array.Empty<WanHealthEvent>();

    public Guid? ActiveInterfaceId    { get; init; }
    public string? ActiveInterfaceName { get; init; }
    public DateTime? ActiveSince      { get; init; }

    public Guid? OverrideInterfaceId   { get; init; }
    public string? OverrideInterfaceName { get; init; }
    public string? OverrideSetBy       { get; init; }

    /// <summary>True when an operator has pinned a WAN (manual mode); false = auto.</summary>
    public bool IsOverridden => OverrideInterfaceId is not null;

    /// <summary>True when no enabled config rows exist — failover isn't armed.</summary>
    public bool NotConfigured => Wans.Count == 0;

    /// <summary>
    /// True when the rows came from the instant-ping fallback (daemon
    /// <c>GetWanStatusAsync</c>) rather than the persisted hysteresis state.
    /// The card surfaces this so operators know the data has no thresholds.
    /// </summary>
    public bool IsFallback { get; init; }

    // ───────────── presentation options (set by each consumer) ─────────────

    public WanCardOptions Options { get; init; } = WanCardOptions.Default;

    public sealed class WanHealthCardRow
    {
        public Guid InterfaceId      { get; init; }
        public string Name           { get; init; } = string.Empty;
        public string Role           { get; init; } = string.Empty;
        public bool IsUp             { get; init; }
        public bool IsActive         { get; init; }
        public bool IsPinned         { get; init; }
        public int ConsecutiveFailures  { get; init; }
        public int ConsecutiveSuccesses { get; init; }
        public double? LastRttMs     { get; init; }
        public string? LastTarget    { get; init; }
        public string? LastError     { get; init; }
        public DateTime? LastCheckAt { get; init; }
    }
}

/// <summary>How a WAN-health card should render. Each surface picks the mix it needs.</summary>
public sealed class WanCardOptions
{
    /// <summary>Render Configure / Make-active / Return-to-auto controls (failover page only).</summary>
    public bool ShowControls { get; init; }

    /// <summary>Render the recent-transitions timeline below the rows.</summary>
    public bool ShowEvents { get; init; }

    /// <summary>Show consecutive failure/success counters per WAN.</summary>
    public bool ShowHysteresis { get; init; } = true;

    /// <summary>Show the Automatic/Pinned mode banner at the top.</summary>
    public bool ShowModeBanner { get; init; } = true;

    /// <summary>
    /// When no <c>wan_health_config</c> rows exist, fall back to the daemon's
    /// instant-ping snapshot (<c>GetWanStatusAsync</c>) so the card isn't empty.
    /// The dashboard wants this; the failover page shows its own empty-state instead.
    /// </summary>
    public bool AllowPingFallback { get; init; }

    /// <summary>Link target for the "Manage →" affordance (null = no link, e.g. on the failover page itself).</summary>
    public string? ManageUrl { get; init; }

    public WanCardLayout Layout { get; init; } = WanCardLayout.List;

    /// <summary>Full interactive panel: cards grid, controls, events, hysteresis. Used by /Network/Wan.</summary>
    public static WanCardOptions Panel(string? manageUrl = null) => new()
    {
        ShowControls = true,
        ShowEvents = true,
        ShowHysteresis = true,
        ShowModeBanner = true,
        Layout = WanCardLayout.Cards,
        ManageUrl = manageUrl,
    };

    /// <summary>Read-only live pod for the Monitoring page (compact list, no controls).</summary>
    public static WanCardOptions Pod(string manageUrl) => new()
    {
        ShowControls = false,
        ShowEvents = false,
        ShowHysteresis = false,
        ShowModeBanner = true,
        Layout = WanCardLayout.List,
        ManageUrl = manageUrl,
    };

    /// <summary>Compact dashboard summary (no mode banner, no controls, no events; ping fallback on).</summary>
    public static WanCardOptions Summary(string manageUrl) => new()
    {
        ShowControls = false,
        ShowEvents = false,
        ShowHysteresis = true,
        ShowModeBanner = false,
        AllowPingFallback = true,
        Layout = WanCardLayout.List,
        ManageUrl = manageUrl,
    };

    public static readonly WanCardOptions Default = Summary("");
}

public enum WanCardLayout
{
    /// <summary>Compact vertical list with dividers (pod / dashboard).</summary>
    List,
    /// <summary>Two-column grid of per-WAN cards (failover page).</summary>
    Cards,
}
