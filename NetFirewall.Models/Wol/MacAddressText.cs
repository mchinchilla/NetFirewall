using System.Text;

namespace NetFirewall.Models.Wol;

/// <summary>
/// The MAC spellings operators actually paste — <c>AA:BB:CC:DD:EE:FF</c>,
/// <c>aa-bb-cc-dd-ee-ff</c>, Cisco's <c>aabb.ccdd.eeff</c> and bare
/// <c>AABBCCDDEEFF</c> — turned into six bytes plus one canonical form
/// (upper-case, colon-separated). Pure: the Web form, the Web controller and the
/// daemon all call it, so the three agree on what a device address is.
/// </summary>
public static class MacAddressText
{
    /// <summary>
    /// HTML5 <c>pattern</c> accepting the same spellings as <see cref="TryParse"/>
    /// (the browser wraps it in <c>^(?:…)$</c> itself). Hyphens inside the class
    /// are escaped because browsers compile patterns with the <c>v</c> flag.
    /// </summary>
    public const string Pattern =
        @"\s*(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\s*|\s*[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\s*|\s*[0-9A-Fa-f]{12}\s*";

    public static bool TryParse(string? input, out byte[] bytes, out string normalized, out string? error)
    {
        bytes = [];
        normalized = string.Empty;
        error = null;

        var s = (input ?? string.Empty).Trim();
        if (s.Length == 0)
        {
            error = "MAC address is required.";
            return false;
        }

        string? hex = s.Length switch
        {
            17 => Grouped(s, groupLen: 2, groups: 6, seps: ":-"),
            14 => Grouped(s, groupLen: 4, groups: 3, seps: "."),
            12 => s,
            _ => null,
        };
        if (hex is null || !hex.All(Uri.IsHexDigit))
        {
            error = "MAC address: six hex pairs, e.g. AA:BB:CC:DD:EE:FF (':' '-' '.' or no separator).";
            return false;
        }

        var parsed = Convert.FromHexString(hex);
        if (parsed.All(b => b == 0))
        {
            error = "00:00:00:00:00:00 is not a device address.";
            return false;
        }
        // I/G bit: a network card's own address is always unicast. A multicast or
        // broadcast address here is a typo, and the NIC would never match it.
        if ((parsed[0] & 0x01) != 0)
        {
            error = "That is a multicast/broadcast address, not a network card's address.";
            return false;
        }

        bytes = parsed;
        normalized = Format(parsed);
        return true;
    }

    /// <summary>Canonical <c>AA:BB:CC:DD:EE:FF</c> or null when <paramref name="input"/> is not a device MAC.</summary>
    public static string? Normalize(string? input) =>
        TryParse(input, out _, out var normalized, out _) ? normalized : null;

    public static string Format(ReadOnlySpan<byte> mac) =>
        string.Join(':', mac.ToArray().Select(b => b.ToString("X2")));

    /// <summary>Strips the separators when every one sits exactly where it should; null otherwise.</summary>
    private static string? Grouped(string s, int groupLen, int groups, string seps)
    {
        var hex = new StringBuilder(12);
        for (var g = 0; g < groups; g++)
        {
            var start = g * (groupLen + 1);
            hex.Append(s, start, groupLen);
            if (g < groups - 1 && seps.IndexOf(s[start + groupLen]) < 0) return null;
        }
        return hex.ToString();
    }
}
