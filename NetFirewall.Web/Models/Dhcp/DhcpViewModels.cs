using System.ComponentModel.DataAnnotations;
using System.Net;
using NetFirewall.Web.Models.Network;

namespace NetFirewall.Web.Models.Dhcp;

// =====================================================================
//  Subnet form
// =====================================================================

public sealed class SubnetFormViewModel : IValidatableObject
{
    public Guid? Id { get; set; }

    [Required, StringLength(100, MinimumLength = 1)]
    public string Name { get; set; } = string.Empty;

    [Required, RegularExpression(@"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$",
        ErrorMessage = "Network must be IPv4 CIDR (e.g. 192.168.10.0/24).")]
    public string Network { get; set; } = string.Empty;

    [Required, IPv4] public string SubnetMask { get; set; } = "255.255.255.0";

    [IPv4(AllowEmpty = true)] public string? Router { get; set; }
    [IPv4(AllowEmpty = true)] public string? Broadcast { get; set; }

    [StringLength(255)] public string? DomainName { get; set; }
    public string? DnsServersRaw { get; set; }     // comma-separated IPv4 list
    public string? NtpServersRaw { get; set; }
    public string? WinsServersRaw { get; set; }

    [Range(60, 30 * 86400, ErrorMessage = "Default lease time must be 60s – 30 days.")]
    public int DefaultLeaseTime { get; set; } = 86400;

    [Range(60, 30 * 86400, ErrorMessage = "Max lease time must be 60s – 30 days.")]
    public int MaxLeaseTime { get; set; } = 604800;

    [Range(576, 9216)] public int? InterfaceMtu { get; set; }

    [StringLength(255)] public string? TftpServer { get; set; }
    [StringLength(255)] public string? BootFilename { get; set; }
    [StringLength(255)] public string? BootFilenameUefi { get; set; }

    [StringLength(2000)] public string? DomainSearchList { get; set; }

    public Guid? InterfaceId { get; set; }
    public bool Enabled { get; set; } = true;

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (MaxLeaseTime < DefaultLeaseTime)
            yield return new ValidationResult(
                "Max lease time must be greater than or equal to default lease time.",
                new[] { nameof(MaxLeaseTime) });

        foreach (var (raw, name) in new[] {
            (DnsServersRaw, nameof(DnsServersRaw)),
            (NtpServersRaw, nameof(NtpServersRaw)),
            (WinsServersRaw, nameof(WinsServersRaw)) })
        {
            if (string.IsNullOrWhiteSpace(raw)) continue;
            var bad = raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                         .Where(s => !IPAddress.TryParse(s, out _))
                         .ToList();
            if (bad.Count > 0)
                yield return new ValidationResult(
                    $"Invalid entries: {string.Join(", ", bad)}", new[] { name });
        }
    }
}

// =====================================================================
//  Pool form
// =====================================================================

public sealed class PoolFormViewModel : IValidatableObject
{
    public Guid? Id { get; set; }

    [Required] public Guid SubnetId { get; set; }

    [StringLength(100)] public string? Name { get; set; }

    [Required, IPv4] public string RangeStart { get; set; } = string.Empty;
    [Required, IPv4] public string RangeEnd   { get; set; } = string.Empty;

    public bool AllowUnknownClients { get; set; } = true;
    public bool DenyBootp { get; set; }
    public bool KnownClientsOnly { get; set; }

    [Range(0, 1000)] public int Priority { get; set; } = 100;
    public bool Enabled { get; set; } = true;

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (IPAddress.TryParse(RangeStart, out var s) && IPAddress.TryParse(RangeEnd, out var e))
        {
            if (CompareIPv4(s, e) > 0)
                yield return new ValidationResult(
                    "Range start must come before range end.",
                    new[] { nameof(RangeStart) });
        }
    }

    private static int CompareIPv4(IPAddress a, IPAddress b)
    {
        var ab = a.GetAddressBytes();
        var bb = b.GetAddressBytes();
        for (var i = 0; i < 4; i++)
        {
            if (ab[i] != bb[i]) return ab[i].CompareTo(bb[i]);
        }
        return 0;
    }
}

// =====================================================================
//  Reservation form
// =====================================================================

public sealed class ReservationFormViewModel
{
    public Guid? Id { get; set; }

    [Required, RegularExpression(@"^([0-9A-Fa-f]{2}([:-])){5}[0-9A-Fa-f]{2}$",
        ErrorMessage = "MAC must be in xx:xx:xx:xx:xx:xx form.")]
    public string MacAddress { get; set; } = string.Empty;

    [Required, IPv4] public string ReservedIp { get; set; } = string.Empty;

    [StringLength(255)] public string? Description { get; set; }
}
