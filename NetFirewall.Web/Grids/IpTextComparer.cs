using System.Net;

namespace NetFirewall.Web.Grids;

/// <summary>
/// Orders address text the way an operator reads it: 10.0.0.9 before 10.0.0.10, IPv4 before
/// IPv6, and anything that isn't an address (a CIDR, a name, empty) after both, ordinally.
/// Parses from the span (no substring per comparison; it runs inside the grid's sort).
/// </summary>
public sealed class IpTextComparer : IComparer<string>
{
    public static readonly IpTextComparer Instance = new();

    public int Compare(string? x, string? y)
    {
        var kx = Key(x, out var vx);
        var ky = Key(y, out var vy);
        if (kx != ky) return kx.CompareTo(ky);
        return kx switch
        {
            0 or 1 => vx.CompareTo(vy),
            _ => string.CompareOrdinal(x, y),
        };
    }

    // 0 = IPv4 (value = address), 1 = IPv6 (value = address), 2 = other text.
    private static int Key(string? text, out UInt128 value)
    {
        value = 0;
        if (string.IsNullOrEmpty(text)) return 2;
        var span = text.AsSpan();
        var slash = span.IndexOf('/');
        if (slash >= 0) span = span[..slash];   // a CIDR sorts by its network address
        if (!IPAddress.TryParse(span, out var ip)) return 2;
        Span<byte> bytes = stackalloc byte[16];
        if (!ip.TryWriteBytes(bytes, out var written)) return 2;
        for (var i = 0; i < written; i++) value = (value << 8) | bytes[i];
        return written == 4 ? 0 : 1;
    }
}
