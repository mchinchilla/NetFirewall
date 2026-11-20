using System.Text.RegularExpressions;

namespace NetFirewall.Models.Vpn;

/// <summary>
/// WireGuard interface names. The name becomes a Linux link name (≤ 15 chars), a file name
/// (/etc/wireguard/{name}.conf) and an argument to wg-quick — so only a strict charset is
/// accepted, everywhere a name enters the system (form, import, generated). New outbound
/// client connections get generated names (wgc1, wgc2 …), never typed ones. Pure, no IO.
/// </summary>
public static partial class WgInterfaceName
{
    public const string ServerDefault = "wg0";
    public const string ClientPrefix = "wgc";

    public static bool IsValid(string? name) => name is not null && Pattern().IsMatch(name);

    /// <summary>The first free "wgcN" (N ≥ 1) not in <paramref name="taken"/>.</summary>
    public static string NextClientName(IEnumerable<string> taken)
    {
        var used = taken.ToHashSet(StringComparer.Ordinal);
        for (var n = 1; ; n++)
        {
            var candidate = $"{ClientPrefix}{n}";
            if (!used.Contains(candidate)) return candidate;
        }
    }

    [GeneratedRegex(@"^[A-Za-z0-9_.\-]{1,15}$")]
    private static partial Regex Pattern();
}
