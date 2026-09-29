using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Net.Sockets;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Models.Wol;

namespace NetFirewall.Web.Models.Network;

/// <summary>HTML5 patterns shared by the Wake-on-LAN forms (client half of rule #4).</summary>
public static class WolPatterns
{
    public const string Mac = MacAddressText.Pattern;
    public const string Iface = @"[A-Za-z0-9_.\-]{1,15}";
    public const string Ipv4 = @"(?:\d{1,3}\.){3}\d{1,3}";
}

/// <summary>Add / edit drawer for a saved device.</summary>
public sealed class WolDeviceFormViewModel : IValidatableObject
{
    public Guid? Id { get; set; }

    [Required, StringLength(64)]
    public string Name { get; set; } = string.Empty;

    [Required(ErrorMessage = "MAC address is required.")]
    public string MacAddress { get; set; } = string.Empty;

    [Required(ErrorMessage = "Pick the interface the device is plugged into.")]
    [RegularExpression("^" + WolPatterns.Iface + "$", ErrorMessage = "Interface: 1-15 chars of letters, digits, '.', '_' or '-'.")]
    public string Interface { get; set; } = string.Empty;

    [Range(1, 65535, ErrorMessage = "Port must be 1-65535.")]
    public int Port { get; set; } = WolDefaults.Port;

    [StringLength(255)]
    public string? Description { get; set; }

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (!string.IsNullOrWhiteSpace(MacAddress) && !MacAddressText.TryParse(MacAddress, out _, out _, out var error))
            yield return new ValidationResult(error, [nameof(MacAddress)]);
    }

    public static WolDeviceFormViewModel From(WolDevice d) => new()
    {
        Id = d.Id,
        Name = d.Name,
        MacAddress = d.MacAddress,
        Interface = d.Interface,
        Port = d.Port,
        Description = d.Description,
    };

    public WolDevice ToEntity() => new()
    {
        Id = Id ?? Guid.Empty,
        Name = Name,
        MacAddress = MacAddress,
        Interface = Interface,
        Port = Port,
        Description = Description,
    };
}

/// <summary>
/// One-off wake: the quick form on the Wake-on-LAN page and the Wake buttons on the
/// DHCP reservation / lease rows (those post the MAC plus the row's IP as the hint).
/// </summary>
public sealed class WolWakeFormViewModel : IValidatableObject
{
    [Required(ErrorMessage = "MAC address is required.")]
    public string MacAddress { get; set; } = string.Empty;

    [RegularExpression("^" + WolPatterns.Iface + "$", ErrorMessage = "Interface: 1-15 chars of letters, digits, '.', '_' or '-'.")]
    public string? Interface { get; set; }

    /// <summary>An address on the device's subnet; the daemon picks the link that holds it.</summary>
    public string? IpHint { get; set; }

    [Range(1, 65535, ErrorMessage = "Port must be 1-65535.")]
    public int? Port { get; set; }

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (!string.IsNullOrWhiteSpace(MacAddress) && !MacAddressText.TryParse(MacAddress, out _, out _, out var error))
            yield return new ValidationResult(error, [nameof(MacAddress)]);

        if (!string.IsNullOrWhiteSpace(IpHint) && !IsDottedQuad(IpHint))
            yield return new ValidationResult($"'{IpHint.Trim()}' is not an IPv4 address.", [nameof(IpHint)]);

        if (string.IsNullOrWhiteSpace(Interface) && string.IsNullOrWhiteSpace(IpHint))
            yield return new ValidationResult("Pick the interface the device is plugged into.", [nameof(Interface)]);
    }

    public WolWakeRequest ToRequest() => new(
        MacAddress.Trim(),
        string.IsNullOrWhiteSpace(Interface) ? null : Interface.Trim(),
        string.IsNullOrWhiteSpace(IpHint) ? null : IpHint.Trim(),
        Port);

    private static bool IsDottedQuad(string value)
    {
        var t = value.Trim();
        return t.Count(c => c == '.') == 3
               && IPAddress.TryParse(t, out var ip)
               && ip.AddressFamily == AddressFamily.InterNetwork;
    }
}

public sealed class WolPageViewModel
{
    /// <summary>Configured LAN-side links (WAN and VPN left out: a wake never goes there).</summary>
    public IReadOnlyList<FormFieldViewModel.SelectOption> InterfaceOptions { get; init; } = [];
    public bool DaemonEnabled { get; init; }
}

public sealed class WolDeviceFormPageViewModel
{
    public required WolDeviceFormViewModel Form { get; init; }
    public IReadOnlyList<FormFieldViewModel.SelectOption> InterfaceOptions { get; init; } = [];
}

public sealed record WolDeviceRow(WolDevice Device, WolPresence Presence);

/// <param name="OutOfBand">True when rendered by the presence poll (<c>hx-swap-oob</c>).</param>
public sealed record WolPresenceBadgeViewModel(Guid DeviceId, WolPresence Presence, bool OutOfBand = false);

public sealed record WolPresenceErrorViewModel(string? Error, bool OutOfBand = false);

public sealed class WolDevicesTableViewModel
{
    public IReadOnlyList<WolDeviceRow> Rows { get; init; } = [];

    /// <summary>Why presence could not be read (daemon down / disabled); rows still render.</summary>
    public string? PresenceError { get; init; }
}

/// <summary>
/// What the firewall's ARP table says about a device — the honest answer to
/// "did it wake?". Only REACHABLE means the NIC answered in the last half-minute;
/// STALE is merely remembered, and a machine that never talks to the firewall is
/// absent even while it is running.
/// </summary>
public sealed record WolPresence(string Label, string BadgeClass, string Title, string? Ip)
{
    public static WolPresence From(NeighborEntry? n) => n is null
        ? new("not seen", "badge-muted", "Not in the firewall's ARP table.", null)
        : n.State.ToUpperInvariant() switch
    {
        "REACHABLE" or "PERMANENT" => new("online", "badge-success", $"Answered ARP recently at {n.Ip} on {n.Dev}.", n.Ip),
        "DELAY" or "PROBE" => new("checking", "badge-info", $"The firewall is re-checking {n.Ip} on {n.Dev}.", n.Ip),
        "FAILED" or "INCOMPLETE" => new("offline", "badge-danger", $"{n.Ip} did not answer ARP on {n.Dev}.", n.Ip),
        _ => new("idle", "badge-muted", $"Known at {n.Ip} on {n.Dev}, not confirmed recently ({n.State}).", n.Ip),
    };

    /// <summary>
    /// A MAC can sit in the table several times (one row per IP). The most alive
    /// entry wins: an old FAILED row for a previous address must not hide a
    /// REACHABLE one.
    /// </summary>
    public static WolPresence For(string mac, IEnumerable<NeighborEntry> neighbors)
    {
        NeighborEntry? best = null;
        foreach (var n in neighbors)
        {
            if (!string.Equals(MacAddressText.Normalize(n.Mac), mac, StringComparison.Ordinal)) continue;
            if (best is null || Rank(n.State) > Rank(best.State)) best = n;
        }
        return From(best);
    }

    private static int Rank(string state) => state.ToUpperInvariant() switch
    {
        "REACHABLE" or "PERMANENT" => 4,
        "DELAY" or "PROBE" => 3,
        "STALE" or "NOARP" => 2,
        _ => 1,
    };
}
