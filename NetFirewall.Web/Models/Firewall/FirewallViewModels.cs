using System.ComponentModel.DataAnnotations;
using System.Net;
using NetFirewall.Web.Models.Network;

namespace NetFirewall.Web.Models.Firewall;

// =====================================================================
//  Filter rules (input / forward / output chains)
// =====================================================================

public sealed class FilterRuleFormViewModel
{
    public Guid? Id { get; set; }

    [Required, RegularExpression("^(input|forward|output)$",
        ErrorMessage = "Chain must be input, forward or output.")]
    public string Chain { get; set; } = "input";

    [StringLength(255)] public string? Description { get; set; }

    [Required, RegularExpression("^(accept|drop|reject|log)$",
        ErrorMessage = "Action must be accept, drop, reject or log.")]
    public string Action { get; set; } = "accept";

    [RegularExpression("^(tcp|udp|icmp|icmpv6|sctp)?$",
        ErrorMessage = "Pick a protocol or leave blank for any.")]
    public string? Protocol { get; set; }

    public Guid? InterfaceInId  { get; set; }
    public Guid? InterfaceOutId { get; set; }

    /// <summary>Comma-separated source addresses / CIDRs.</summary>
    public string? SourceAddresses { get; set; }
    public string? DestinationAddresses { get; set; }

    /// <summary>Comma-separated ports (e.g. <c>22, 80, 443, 8000-9000</c>).</summary>
    public string? DestinationPorts { get; set; }

    /// <summary>Comma-separated states: new, established, related, invalid.</summary>
    public string? ConnectionStates { get; set; }

    /// <summary>nftables-style rate limit, e.g. <c>10/second</c>.</summary>
    [RegularExpression(@"^\d+/(second|minute|hour|day)$|^$",
        ErrorMessage = "Format: N/(second|minute|hour|day) — leave empty for no limit.")]
    public string? RateLimit { get; set; }

    [StringLength(50)] public string? LogPrefix { get; set; }

    [Range(0, 10000)] public int Priority { get; set; } = 100;
    public bool Enabled { get; set; } = true;
}

// =====================================================================
//  Port forwards (DNAT)
// =====================================================================

public sealed class PortForwardFormViewModel : IValidatableObject
{
    public Guid? Id { get; set; }

    [StringLength(255)] public string? Description { get; set; }

    [Required, RegularExpression("^(tcp|udp|tcp/udp)$",
        ErrorMessage = "Protocol must be tcp, udp or tcp/udp.")]
    public string Protocol { get; set; } = "tcp";

    public Guid? InterfaceId { get; set; }

    /// <summary>Comma-separated permitted sources (CIDRs); empty = any.</summary>
    public string? SourceAddresses { get; set; }

    [Range(1, 65535)] public int ExternalPortStart { get; set; } = 0;
    [Range(1, 65535)] public int? ExternalPortEnd { get; set; }

    [Required, IPv4] public string InternalIp { get; set; } = string.Empty;
    [Range(1, 65535)] public int InternalPort { get; set; } = 0;

    [Range(0, 10000)] public int Priority { get; set; } = 100;
    public bool Enabled { get; set; } = true;

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (ExternalPortEnd.HasValue && ExternalPortEnd.Value < ExternalPortStart)
            yield return new ValidationResult("External port end must be ≥ start.", new[] { nameof(ExternalPortEnd) });
    }
}

// =====================================================================
//  NAT rules (masquerade / SNAT)
// =====================================================================

public sealed class NatRuleFormViewModel : IValidatableObject
{
    public Guid? Id { get; set; }

    [Required, RegularExpression("^(masquerade|snat)$",
        ErrorMessage = "Type must be masquerade or snat.")]
    public string Type { get; set; } = "masquerade";

    [StringLength(255)] public string? Description { get; set; }

    [Required, RegularExpression(@"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$",
        ErrorMessage = "Source network must be CIDR (e.g. 192.168.10.0/24).")]
    public string SourceNetwork { get; set; } = string.Empty;

    public Guid? OutputInterfaceId { get; set; }

    [IPv4(AllowEmpty = true)] public string? SnatAddress { get; set; }

    [Range(0, 10000)] public int Priority { get; set; } = 100;
    public bool Enabled { get; set; } = true;

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (Type == "snat" && string.IsNullOrWhiteSpace(SnatAddress))
            yield return new ValidationResult("SNAT requires a static address.", new[] { nameof(SnatAddress) });
    }
}

// =====================================================================
//  Traffic marks (referenced by mangle rules + qos classes)
// =====================================================================

public sealed class TrafficMarkFormViewModel
{
    public Guid? Id { get; set; }

    [Required, StringLength(50)] public string Name { get; set; } = string.Empty;

    [Required, Range(1, int.MaxValue, ErrorMessage = "Mark value must be a positive integer (e.g. 256 = 0x100).")]
    public int MarkValue { get; set; }

    [StringLength(255)] public string? Description { get; set; }
    [StringLength(50)]  public string? RouteTable { get; set; }
}

// =====================================================================
//  Mangle rules (mark traffic for QoS / policy routing)
// =====================================================================

public sealed class MangleRuleFormViewModel
{
    public Guid? Id { get; set; }

    [Required, RegularExpression("^(prerouting|postrouting)$",
        ErrorMessage = "Chain must be prerouting or postrouting.")]
    public string Chain { get; set; } = "prerouting";

    [StringLength(255)] public string? Description { get; set; }

    public Guid? MarkId { get; set; }

    [RegularExpression("^(tcp|udp|icmp|icmpv6|sctp)?$")]
    public string? Protocol { get; set; }

    public string? SourceAddresses { get; set; }
    public string? DestinationAddresses { get; set; }
    public string? DestinationPorts { get; set; }

    [Range(0, 10000)] public int Priority { get; set; } = 100;
    public bool Enabled { get; set; } = true;
}

// =====================================================================
//  Mapping helpers — pure, no IO. Lifts arrays in/out of the comma form.
// =====================================================================

public static class FwArrayHelpers
{
    public static string? Join(IEnumerable<string>? items) =>
        items is null ? null : string.Join(", ", items.Where(s => !string.IsNullOrWhiteSpace(s)));

    public static string[]? Split(string? raw) =>
        string.IsNullOrWhiteSpace(raw)
            ? null
            : raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToArray();
}
