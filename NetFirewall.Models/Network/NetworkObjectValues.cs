using System.Net;
using System.Net.Sockets;

namespace NetFirewall.Models.Network;

/// <summary>
/// Host/network objects may list several addresses in <see cref="NetworkObject.Value"/>
/// (comma, semicolon, newline, or space). The resolver expands each token.
/// </summary>
public static class NetworkObjectValues
{
    private static readonly char[] Separators = [',', ';', '\n', '\r', '\t'];

    public static string[] Split(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return [];
        return raw
            .Split(Separators, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .SelectMany(part => part.Contains(' ')
                ? part.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                : [part])
            .Where(s => s.Length > 0)
            .ToArray();
    }

    public static bool IsIpv4Host(string token)
    {
        var t = token.Trim();
        if (t.EndsWith("/32", StringComparison.Ordinal)) t = t[..^3];
        return IsDottedQuad(t);
    }

    /// <summary>
    /// A full dotted quad, and nothing shorter. <c>IPAddress.TryParse</c> accepts
    /// the classful shorthand — "9" parses as 0.0.0.9 and "10.0.1" as 10.0.0.1 —
    /// which on a firewall is always a typo, and one nft would reject at apply
    /// time after the object had already been saved.
    /// </summary>
    private static bool IsDottedQuad(string value)
    {
        var t = value.Trim();
        if (t.Count(c => c == '.') != 3) return false;
        return IPAddress.TryParse(t, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork;
    }

    /// <summary>
    /// An inclusive IPv4 range, <c>start-end</c>. nft takes this literal as-is, and
    /// the resolver passes it through untouched, so a list object may hold one
    /// alongside plain hosts.
    /// </summary>
    public static bool IsIpv4Range(string token)
    {
        var t = token.Trim();
        var dash = t.IndexOf('-');
        if (dash <= 0 || dash == t.Length - 1) return false;

        return IsDottedQuad(t[..dash]) && IsDottedQuad(t[(dash + 1)..]);
    }

    public static string CanonicalHost(string token)
    {
        var t = token.Trim();
        if (t.EndsWith("/32", StringComparison.Ordinal)) t = t[..^3];
        return t;
    }
}
