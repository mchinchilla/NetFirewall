using System.ComponentModel.DataAnnotations;
using NetFirewall.Models.WanMonitor;

namespace NetFirewall.Web.Models.Network;

/// <summary>
/// Everything the WAN failover page's live panel renders: per-WAN health,
/// which one is active, whether an operator pinned one, and the recent
/// transition timeline.
/// </summary>
public sealed class WanFailoverPanelViewModel
{
    public IReadOnlyList<WanRow> Wans { get; init; } = Array.Empty<WanRow>();
    public IReadOnlyList<WanHealthEvent> RecentEvents { get; init; } = Array.Empty<WanHealthEvent>();

    public Guid? ActiveInterfaceId   { get; init; }
    public string? ActiveInterfaceName { get; init; }
    public DateTime? ActiveSince     { get; init; }

    public Guid? OverrideInterfaceId { get; init; }
    public string? OverrideInterfaceName { get; init; }
    public string? OverrideSetBy     { get; init; }

    /// <summary>True when an operator has pinned a WAN (manual mode); false = auto.</summary>
    public bool IsOverridden => OverrideInterfaceId is not null;

    /// <summary>True when the daemon reported no config rows — failover isn't armed.</summary>
    public bool NotConfigured => Wans.Count == 0;

    /// <summary>One row per configured WAN, health + role + whether it's active/pinned.</summary>
    public sealed class WanRow
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

/// <summary>
/// Edit form for one wan_health_config row. Bound server-side; validated both
/// sides per project rule #4.
/// </summary>
public sealed class WanConfigFormViewModel
{
    [Required]
    public Guid InterfaceId { get; set; }

    public string InterfaceName { get; set; } = string.Empty;

    [Range(1, 1000, ErrorMessage = "Priority must be between 1 and 1000 (lower = preferred).")]
    public int Priority { get; set; } = 100;

    /// <summary>Comma/space/newline-separated IPs. Empty = ping the gateway.</summary>
    public string? MonitorTargets { get; set; }

    /// <summary>fwmark for probe packets (decimal). Empty = legacy -I probing.</summary>
    [Range(1, 4294967295, ErrorMessage = "fwmark must be a positive integer (e.g. 256 for 0x100).")]
    public long? ProbeFwmark { get; set; }

    [Range(1, 100, ErrorMessage = "Failover threshold must be 1–100.")]
    public int FailoverThreshold { get; set; } = 3;

    [Range(1, 100, ErrorMessage = "Recovery threshold must be 1–100.")]
    public int RecoveryThreshold { get; set; } = 5;

    public bool Enabled { get; set; } = true;
}
