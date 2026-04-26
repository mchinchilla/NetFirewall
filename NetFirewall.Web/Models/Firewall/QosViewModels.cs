using System.ComponentModel.DataAnnotations;

namespace NetFirewall.Web.Models.Firewall;

// =====================================================================
//  QoS config (one per interface — bandwidth cap)
// =====================================================================

public sealed class QosConfigFormViewModel
{
    public Guid? Id { get; set; }

    [Required] public Guid InterfaceId { get; set; }

    [Required, Range(1, 100_000, ErrorMessage = "Total bandwidth must be 1-100000 Mbps.")]
    public int TotalBandwidthMbps { get; set; }

    public bool Enabled { get; set; } = true;
}

// =====================================================================
//  QoS class (HTB child of a config)
// =====================================================================

public sealed class QosClassFormViewModel : IValidatableObject
{
    public Guid? Id { get; set; }
    [Required] public Guid QosConfigId { get; set; }

    [Required, StringLength(50)] public string Name { get; set; } = string.Empty;

    public Guid? MarkId { get; set; }

    [Required, Range(1, 100_000)] public int GuaranteedMbps { get; set; }
    [Required, Range(1, 100_000)] public int CeilingMbps { get; set; }

    [Required, Range(1, 7, ErrorMessage = "Priority is 1 (highest) to 7 (lowest).")]
    public int Priority { get; set; } = 4;

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (CeilingMbps < GuaranteedMbps)
            yield return new ValidationResult(
                "Ceiling (max) must be ≥ guaranteed (rate).",
                new[] { nameof(CeilingMbps) });
    }
}
