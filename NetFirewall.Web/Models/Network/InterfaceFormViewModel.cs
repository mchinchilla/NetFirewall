using System.ComponentModel.DataAnnotations;
using System.Net;

namespace NetFirewall.Web.Models.Network;

/// <summary>
/// Form input for editing a single interface. DataAnnotations cover the
/// server-side half of project rule #4; the matching client-side checks
/// (HTML5 + Alpine guards) are wired in <c>_InterfaceForm.cshtml</c>.
/// </summary>
public sealed class InterfaceFormViewModel : IValidatableObject
{
    public Guid? Id { get; set; }

    [Required, RegularExpression(@"^[a-zA-Z0-9_.\-]{1,15}$",
        ErrorMessage = "Interface name must be 1-15 chars (letters, digits, _ . -)")]
    public string Name { get; set; } = string.Empty;

    [Required, RegularExpression(@"^(WAN|LAN|VPN|DISABLED)$",
        ErrorMessage = "Type must be WAN, LAN, VPN or DISABLED")]
    public string Type { get; set; } = "LAN";

    public string? Role { get; set; }

    [Required, RegularExpression(@"^(static|dhcp|disabled)$")]
    public string AddressingMode { get; set; } = "static";

    [IPv4(AllowEmpty = true)] public string? IpAddress { get; set; }
    [IPv4(AllowEmpty = true)] public string? SubnetMask { get; set; }
    [IPv4(AllowEmpty = true)] public string? Gateway { get; set; }

    /// <summary>Comma-separated list of IPv4 DNS servers.</summary>
    public string? DnsServers { get; set; }

    [Range(576, 9000, ErrorMessage = "MTU must be between 576 and 9000")]
    public int? Mtu { get; set; }

    [Range(1, 4094, ErrorMessage = "VLAN ID must be between 1 and 4094")]
    public int? VlanId { get; set; }

    public string? VlanParent { get; set; }

    /// <summary>
    /// Operator-supplied MAC override (clone/spoof). Empty → keep the NIC's
    /// hardware MAC. Same contract as the wizard's <c>SpoofMacAddress</c>.
    /// </summary>
    [RegularExpression(@"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$",
        ErrorMessage = "MAC must be 6 hex octets, e.g. 00:11:22:33:44:55.")]
    public string? MacAddress { get; set; }

    /// <summary>Detected hardware MAC — display-only (placeholder/help text in the form).</summary>
    public string? HardwareMac { get; set; }

    public string? Description { get; set; }

    public bool AutoStart { get; set; } = true;
    public bool Enabled { get; set; } = true;

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        // Static addressing requires IP + mask.
        if (AddressingMode == "static")
        {
            if (string.IsNullOrWhiteSpace(IpAddress))
                yield return new ValidationResult("IP address is required for static addressing.", new[] { nameof(IpAddress) });
            if (string.IsNullOrWhiteSpace(SubnetMask))
                yield return new ValidationResult("Subnet mask is required for static addressing.", new[] { nameof(SubnetMask) });
        }

        // VLAN ID requires a parent interface name.
        if (VlanId.HasValue && string.IsNullOrWhiteSpace(VlanParent))
            yield return new ValidationResult("VLAN parent interface is required when VLAN ID is set.", new[] { nameof(VlanParent) });

        // DNS list — every entry must parse as IPv4.
        if (!string.IsNullOrWhiteSpace(DnsServers))
        {
            var bad = DnsServers.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Where(s => !IPAddress.TryParse(s, out _))
                .ToList();
            if (bad.Count > 0)
                yield return new ValidationResult($"Invalid DNS entries: {string.Join(", ", bad)}", new[] { nameof(DnsServers) });
        }
    }
}

[AttributeUsage(AttributeTargets.Property)]
public sealed class IPv4Attribute : ValidationAttribute
{
    public bool AllowEmpty { get; set; }

    protected override ValidationResult? IsValid(object? value, ValidationContext context)
    {
        var s = value as string;
        if (string.IsNullOrWhiteSpace(s))
            return AllowEmpty ? ValidationResult.Success : new ValidationResult($"{context.DisplayName} is required.");
        return IPAddress.TryParse(s, out var ip) && ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
            ? ValidationResult.Success
            : new ValidationResult($"{context.DisplayName} is not a valid IPv4 address.");
    }
}
