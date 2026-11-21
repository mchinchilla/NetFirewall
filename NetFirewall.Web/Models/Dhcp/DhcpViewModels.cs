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
    // Option 67 carries at most 255 bytes; a longer name made the server drop the reply.
    [StringLength(255)] public string? BootFilenameIpxe { get; set; }

    /// <summary>UEFI HTTP boot URI (00051). Must be http:// or https://.</summary>
    [StringLength(255)] public string? BootFilenameHttp { get; set; }

    /// <summary>ARM64 UEFI boot file over TFTP (00051).</summary>
    [StringLength(255)] public string? BootFilenameArm64 { get; set; }

    [StringLength(2000)] public string? DomainSearchList { get; set; }

    public Guid? InterfaceId { get; set; }
    public bool Enabled { get; set; } = true;

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (MaxLeaseTime < DefaultLeaseTime)
            yield return new ValidationResult(
                "Max lease time must be greater than or equal to default lease time.",
                new[] { nameof(MaxLeaseTime) });

        if (!string.IsNullOrWhiteSpace(BootFilenameHttp) && !NetFirewall.Models.Dhcp.PxeBoot.IsHttpUri(BootFilenameHttp.Trim()))
            yield return new ValidationResult(
                "HTTP boot URI must be an absolute http:// or https:// address.", new[] { nameof(BootFilenameHttp) });

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

    /// <summary>One DNS label, published as &lt;name&gt;.&lt;subnet domain&gt; in the firewall's resolver.</summary>
    [RegularExpression(@"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$",
        ErrorMessage = "Host name: lower-case letters, digits and '-', no dots (e.g. nas, office-printer).")]
    public string? Hostname { get; set; }

    /// <summary>Per-host lease in seconds; empty = the subnet's default lease time.</summary>
    [Range(NetFirewall.Models.Dhcp.DhcpMacReservation.MinLeaseTime, NetFirewall.Models.Dhcp.DhcpMacReservation.MaxLeaseTime,
        ErrorMessage = "Lease time must be 60 seconds – 1 year (31536000 s).")]
    public int? LeaseTime { get; set; }
}

/// <summary>The custom option drawer. Validated here and again (encoding, scope) by IDhcpCustomOptionService.</summary>
public sealed class DhcpOptionFormViewModel
{
    public Guid? Id { get; set; }

    [System.ComponentModel.DataAnnotations.Required(ErrorMessage = "Pick who the option is for.")]
    [System.ComponentModel.DataAnnotations.RegularExpression("^(global|subnet|class|host)$", ErrorMessage = "Pick who the option is for.")]
    public string ScopeType { get; set; } = NetFirewall.Models.Dhcp.DhcpOptionScopes.Global;

    public Guid? ScopeId { get; set; }

    [System.ComponentModel.DataAnnotations.Range(1, 254, ErrorMessage = "Option code must be 1–254.")]
    public int Code { get; set; } = 66;

    [System.ComponentModel.DataAnnotations.StringLength(100)]
    public string? Name { get; set; }

    [System.ComponentModel.DataAnnotations.Required]
    [System.ComponentModel.DataAnnotations.RegularExpression("^(ip|ip_list|string|uint8|uint16|uint32|bool|hex)$", ErrorMessage = "Pick the value format.")]
    public string Format { get; set; } = NetFirewall.Models.Dhcp.DhcpOptionFormats.Text;

    [System.ComponentModel.DataAnnotations.Required(ErrorMessage = "A value is required.")]
    [System.ComponentModel.DataAnnotations.StringLength(1024)]
    public string Value { get; set; } = string.Empty;
}

/// <summary>Drawer model: the form + the targets of its current scope.</summary>
public sealed class DhcpOptionFormPageViewModel
{
    public required DhcpOptionFormViewModel Form { get; init; }
    public IReadOnlyList<(Guid Id, string Label)> Targets { get; init; } = [];
}

// =====================================================================
//  Access control: MAC block list + trusted relays (00053 / 00054)
// =====================================================================

/// <summary>The block-list drawer. Validated here and again by IDhcpAccessControlService.</summary>
public sealed class BlockedMacFormViewModel
{
    public Guid? Id { get; set; }

    [Required(ErrorMessage = "Enter the device's MAC address."),
     RegularExpression(@"^([0-9A-Fa-f]{2}([:-])){5}[0-9A-Fa-f]{2}$", ErrorMessage = "MAC must be in xx:xx:xx:xx:xx:xx form.")]
    public string MacAddress { get; set; } = string.Empty;

    [StringLength(255)] public string? Reason { get; set; }
}

/// <summary>The relay drawer. Validated here and again by IDhcpAccessControlService.</summary>
public sealed class RelayAgentFormViewModel
{
    public Guid? Id { get; set; }

    [Required(ErrorMessage = "Enter the relay's IPv4 address."), IPv4]
    public string IpAddress { get; set; } = string.Empty;

    [StringLength(255)] public string? Description { get; set; }

    public bool Trusted { get; set; } = true;
}
