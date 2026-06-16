using System.ComponentModel.DataAnnotations;

namespace NetFirewall.Web.Models.Network;

// The live failover panel now renders the shared WanHealthCardViewModel
// (see _WanHealthCard.cshtml + IWanHealthCardBuilder). Only the config edit
// form remains here.

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
