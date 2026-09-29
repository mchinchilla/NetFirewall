namespace NetFirewall.Models.Wol;

/// <summary>
/// A machine the operator wakes often enough to keep: a name, the MAC its NIC
/// listens for, and the LAN interface it hangs off. Row of <c>wol_devices</c>.
/// </summary>
public sealed class WolDevice
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;

    /// <summary>Canonical <c>AA:BB:CC:DD:EE:FF</c> (see <see cref="MacAddressText"/>).</summary>
    public string MacAddress { get; set; } = string.Empty;

    /// <summary>Kernel link the magic packet leaves through (a LAN or VLAN interface, never a WAN).</summary>
    public string Interface { get; set; } = string.Empty;

    /// <summary>UDP destination port — 9 (discard) by convention; some NICs/BIOSes want 7.</summary>
    public int Port { get; set; } = WolDefaults.Port;

    public string? Description { get; set; }
    public DateTime? LastWokenAt { get; set; }
    public string? LastWokenBy { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }

    // ── Not persisted: joined from DHCP by MAC so the list shows where the device lives. ──

    /// <summary>Reserved IP, else the most recent lease's IP. Null when DHCP has never seen the MAC.</summary>
    public string? KnownIp { get; set; }

    /// <summary>Hostname from the most recent DHCP lease.</summary>
    public string? KnownHostname { get; set; }
}

public static class WolDefaults
{
    public const int Port = 9;

    /// <summary>Copies of the magic packet per wake. UDP is fire-and-forget; three spaced sends ride out a dropped frame.</summary>
    public const int Copies = 3;
}

/// <summary>
/// One wake. <see cref="Interface"/> wins when set; otherwise the daemon picks the
/// LAN interface whose subnet contains <see cref="IpHint"/> (a DHCP reservation or
/// lease address). With neither the request is refused — broadcasting on every
/// link is not a guess worth making on a firewall.
/// </summary>
public sealed record WolWakeRequest(string Mac, string? Interface = null, string? IpHint = null, int? Port = null);

/// <summary>Outcome of waking every saved device: one item per device, in list order.</summary>
public sealed record WolBatchResult(IReadOnlyList<WolBatchItem> Items)
{
    public int Total => Items.Count;
    public int Sent => Items.Count(i => i.Sent);
}

/// <param name="Error">Why the daemon refused or failed this one; null when sent.</param>
public sealed record WolBatchItem(Guid DeviceId, string Name, bool Sent, string? Interface, string? Error);

/// <param name="Mac">Canonical MAC the packet carries.</param>
/// <param name="Interface">Link it left through.</param>
/// <param name="InterfaceSource">Why that link: <c>requested</c>, or <c>subnet 192.168.10.0/24</c> when resolved from the IP hint.</param>
/// <param name="Destination">UDP destination address (limited broadcast, bound to the link).</param>
/// <param name="Copies">Packets actually sent.</param>
public sealed record WolWakeResult(string Mac, string Interface, string InterfaceSource, string Destination, int Port, int Copies);
