using System.ComponentModel.DataAnnotations;
using System.Net;
using NetFirewall.Web.Models.Network;

namespace NetFirewall.Web.Models.Dhcp;

// =====================================================================
//  Exclusion form (nested under a subnet)
// =====================================================================

public sealed class ExclusionFormViewModel : IValidatableObject
{
    public Guid? Id { get; set; }
    [Required] public Guid SubnetId { get; set; }

    [Required, IPv4] public string IpStart { get; set; } = string.Empty;
    [IPv4(AllowEmpty = true)] public string? IpEnd { get; set; }

    [StringLength(255)] public string? Reason { get; set; }

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (!string.IsNullOrEmpty(IpEnd) &&
            IPAddress.TryParse(IpStart, out var s) &&
            IPAddress.TryParse(IpEnd, out var e))
        {
            if (CompareIPv4(s, e) > 0)
                yield return new ValidationResult(
                    "End must come after start.", new[] { nameof(IpEnd) });
        }
    }

    private static int CompareIPv4(IPAddress a, IPAddress b)
    {
        var ab = a.GetAddressBytes();
        var bb = b.GetAddressBytes();
        for (var i = 0; i < 4; i++)
            if (ab[i] != bb[i]) return ab[i].CompareTo(bb[i]);
        return 0;
    }
}

// =====================================================================
//  Class form
// =====================================================================

public sealed class ClassFormViewModel
{
    public Guid? Id { get; set; }

    [Required, StringLength(100)] public string Name { get; set; } = string.Empty;

    [Required, RegularExpression("^(vendor_class|user_class|mac_prefix|hardware_type|client_id|hostname|option|relay_agent)$",
        ErrorMessage = "Pick one of the supported match types.")]
    public string MatchType { get; set; } = "vendor_class";

    [Required, StringLength(255)] public string MatchValue { get; set; } = string.Empty;

    [IPv4(AllowEmpty = true)] public string? NextServer { get; set; }
    [StringLength(255)]      public string? BootFilename { get; set; }

    [Range(0, 1000)] public int Priority { get; set; } = 100;
    public bool Enabled { get; set; } = true;
}

// =====================================================================
//  DDNS form
// =====================================================================

public sealed class DdnsFormViewModel : IValidatableObject
{
    public Guid? Id { get; set; }

    /// <summary>null = global config, otherwise per-subnet override.</summary>
    public Guid? SubnetId { get; set; }

    public bool EnableForward { get; set; } = true;
    public bool EnableReverse { get; set; } = true;

    [StringLength(255)] public string? ForwardZone { get; set; }
    [StringLength(255)] public string? ReverseZone { get; set; }

    [Required, IPv4] public string DnsServer { get; set; } = string.Empty;
    [Range(1, 65535)] public int DnsPort { get; set; } = 53;

    [StringLength(255)] public string? TsigKeyName { get; set; }
    public string? TsigKeySecret { get; set; }

    [Required, RegularExpression(@"^(hmac-md5\.sig-alg\.reg\.int|hmac-sha1|hmac-sha256|hmac-sha512)$")]
    public string TsigAlgorithm { get; set; } = "hmac-sha256";

    [Range(30, 86400)] public int Ttl { get; set; } = 300;

    [Required, RegularExpression("^(standard|interim|none)$")]
    public string UpdateStyle { get; set; } = "standard";

    public bool OverrideClientUpdate { get; set; }
    public bool AllowClientUpdates { get; set; }

    [Required, RegularExpression("^(check-with-dhcid|no-check|fail-on-conflict)$")]
    public string ConflictResolution { get; set; } = "check-with-dhcid";

    public bool Enabled { get; set; } = true;

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (EnableForward && string.IsNullOrWhiteSpace(ForwardZone))
            yield return new ValidationResult("Forward zone is required when forward updates are enabled.",
                new[] { nameof(ForwardZone) });

        if (!string.IsNullOrEmpty(TsigKeyName) && string.IsNullOrEmpty(TsigKeySecret))
            yield return new ValidationResult("TSIG key secret is required when key name is set.",
                new[] { nameof(TsigKeySecret) });
    }
}

// =====================================================================
//  Failover peer form
// =====================================================================

public sealed class FailoverPeerFormViewModel
{
    public Guid? Id { get; set; }

    [Required, StringLength(100)] public string Name { get; set; } = string.Empty;

    [Required, RegularExpression("^(primary|secondary)$")]
    public string Role { get; set; } = "primary";

    [Required, IPv4] public string PeerAddress { get; set; } = string.Empty;
    [Range(1, 65535)] public int PeerPort { get; set; } = 647;

    [IPv4(AllowEmpty = true)] public string? LocalAddress { get; set; }
    [Range(1, 65535)] public int LocalPort { get; set; } = 647;

    [Range(5, 600)]   public int MaxResponseDelay { get; set; } = 60;
    [Range(1, 1000)]  public int MaxUnackedUpdates { get; set; } = 10;

    [Range(60, 86400)] public int Mclt { get; set; } = 3600;

    [Range(0, 255)]    public int Split { get; set; } = 128;
    [Range(0, 60)]     public int LoadBalanceMax { get; set; } = 3;
    [Range(0, 86400)]  public int AutoPartnerDown { get; set; } = 0;

    [StringLength(512)] public string? SharedSecret { get; set; }

    public bool Enabled { get; set; } = false;
}
