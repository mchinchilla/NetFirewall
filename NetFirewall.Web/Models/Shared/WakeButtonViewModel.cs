namespace NetFirewall.Web.Models.Shared;

/// <summary>
/// The "Wake" button: saved devices post to their own endpoint, DHCP rows post a
/// MAC plus the row's IP (the daemon picks the LAN link whose subnet holds it).
/// </summary>
public sealed class WakeButtonViewModel
{
    /// <summary><c>/Network/WakeOnLan/wake/{id}</c> for a saved device; the ad-hoc endpoint otherwise.</summary>
    public string Url { get; init; } = "/Network/WakeOnLan/wake";

    /// <summary>Form values for the ad-hoc endpoint (MacAddress, IpHint, Interface…); empty for a saved device.</summary>
    public IReadOnlyDictionary<string, string> Values { get; init; } = new Dictionary<string, string>();

    /// <summary>What is being woken, for the tooltip: a device name or a MAC.</summary>
    public required string Subject { get; init; }

    public string Label { get; init; } = "Wake";
}
