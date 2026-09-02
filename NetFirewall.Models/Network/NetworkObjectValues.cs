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
        return IPAddress.TryParse(t, out var ip) && ip.AddressFamily == AddressFamily.InterNetwork;
    }

    public static string CanonicalHost(string token)
    {
        var t = token.Trim();
        if (t.EndsWith("/32", StringComparison.Ordinal)) t = t[..^3];
        return t;
    }
}
