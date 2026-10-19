using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace NetFirewall.Services.Diagnostics;

public sealed partial class DiagnosticInputValidator : IDiagnosticInputValidator
{
    // RFC 1123 hostname: labels of 1-63 [A-Za-z0-9-] not starting/ending with '-', total ≤ 253.
    [GeneratedRegex(@"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")]
    private static partial Regex HostnameRx();

    // Kernel IFNAMSIZ charset/length.
    [GeneratedRegex(@"^[A-Za-z0-9_.\-]{1,15}$")]
    private static partial Regex IfaceRx();

    [GeneratedRegex(@"^(0x[0-9A-Fa-f]{1,8}|[0-9]{1,10})$")]
    private static partial Regex FwmarkRx();

    // pcap-filter syntax only: no quotes, no $ ` ; & newline — nothing shell-shaped.
    [GeneratedRegex(@"^[A-Za-z0-9 ._:/()\[\]<>=!&|,-]+$")]
    private static partial Regex BpfRx();

    [GeneratedRegex(@"^[ \t]*(PrivateKey|PresharedKey)[ \t]*=.*$", RegexOptions.IgnoreCase | RegexOptions.Multiline)]
    private static partial Regex WgSecretLineRx();

    private static readonly HashSet<string> Protos = new(StringComparer.OrdinalIgnoreCase) { "tcp", "udp", "icmp" };

    public bool TryHost(string? input, out string normalized, out string? error)
    {
        normalized = (input ?? string.Empty).Trim();
        if (normalized.Length == 0) { error = "Target is required."; return false; }
        if (normalized[0] == '-')   { error = "Target must not start with '-'."; return false; }

        if (TryIpLiteral(normalized, out var ip))
        {
            normalized = ip.ToString();
            error = null;
            return true;
        }
        // "1.2.3" is a legal RFC 1123 name (all-numeric labels are allowed) but on a
        // firewall it is an incomplete IPv4 nine times out of ten — and ping would
        // silently probe 1.2.0.3. Refuse digits-and-dots that failed the IP check.
        if (normalized.All(c => char.IsAsciiDigit(c) || c == '.'))
        {
            error = "Looks like an incomplete IPv4 address.";
            return false;
        }
        if (HostnameRx().IsMatch(normalized))
        {
            error = null;
            return true;
        }
        error = "Target must be an IPv4/IPv6 address or a hostname.";
        return false;
    }

    public bool TryCidrOrIp(string? input, out string normalized, out string? error)
    {
        normalized = (input ?? string.Empty).Trim();
        if (normalized.Length == 0) { error = "Address is required."; return false; }
        if (normalized[0] == '-')   { error = "Address must not start with '-'."; return false; }

        var slash = normalized.IndexOf('/');
        var host = slash < 0 ? normalized : normalized[..slash];
        if (!TryIpLiteral(host, out var ip))
        {
            error = "Address must be an IP literal or CIDR (e.g. 192.168.99.0/24).";
            return false;
        }
        if (slash >= 0)
        {
            var max = ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            if (!int.TryParse(normalized[(slash + 1)..], out var prefix) || prefix < 0 || prefix > max)
            {
                error = $"Prefix length must be 0-{max}.";
                return false;
            }
            normalized = $"{ip}/{prefix}";
        }
        else
        {
            normalized = ip.ToString();
        }
        error = null;
        return true;
    }

    public bool TryInterfaceName(string? input, IReadOnlySet<string> allowed, out string normalized, out string? error)
    {
        normalized = (input ?? string.Empty).Trim();
        if (normalized.Length == 0) { error = "Interface is required."; return false; }
        if (!IfaceRx().IsMatch(normalized))
        {
            error = "Interface name: 1-15 chars of letters, digits, '.', '_' or '-'.";
            return false;
        }
        if (!allowed.Contains(normalized))
        {
            error = $"Unknown interface '{normalized}'.";
            return false;
        }
        error = null;
        return true;
    }

    public bool TryFwmark(string? input, out long mark, out string? error)
    {
        mark = 0;
        var s = (input ?? string.Empty).Trim();
        if (s.Length == 0) { error = null; return true; }
        if (!FwmarkRx().IsMatch(s))
        {
            error = "Mark must be hex (0x500) or decimal (1280).";
            return false;
        }
        var ok = s.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? long.TryParse(s.AsSpan(2), System.Globalization.NumberStyles.HexNumber, null, out mark)
            : long.TryParse(s, out mark);
        if (!ok || mark < 1 || mark > uint.MaxValue)
        {
            mark = 0;
            error = "Mark must be between 1 and 0xFFFFFFFF.";
            return false;
        }
        error = null;
        return true;
    }

    public bool TryProto(string? input, out string normalized, out string? error)
    {
        normalized = (input ?? string.Empty).Trim().ToLowerInvariant();
        if (normalized.Length == 0) { error = null; return true; }
        if (!Protos.Contains(normalized))
        {
            error = "Protocol must be tcp, udp or icmp.";
            return false;
        }
        error = null;
        return true;
    }

    public bool TryPort(int? input, out int port, out string? error)
    {
        port = input ?? 0;
        if (input is null) { error = null; return true; }
        if (port is < 1 or > 65535)
        {
            error = "Port must be 1-65535.";
            return false;
        }
        error = null;
        return true;
    }

    public bool TryBpfFilter(string? input, out string normalized, out string? error)
    {
        normalized = (input ?? string.Empty).Trim();
        if (normalized.Length == 0) { error = null; return true; }
        if (normalized.Length > 200) { error = "Filter is too long (200 characters max)."; return false; }
        if (normalized[0] == '-') { error = "Filter must not start with '-'."; return false; }
        if (!BpfRx().IsMatch(normalized))
        {
            error = "Filter may only contain letters, digits, spaces and . : / ( ) [ ] < > = ! & | -";
            return false;
        }
        error = null;
        return true;
    }

    public int Clamp(int value, int min, int max) => Math.Clamp(value, min, max);

    public string RedactWgConfig(string text) =>
        string.IsNullOrEmpty(text) ? string.Empty : WgSecretLineRx().Replace(text, "$1 = <redacted>");

    public bool TryTestUrl(string? input, out Uri url, out string? error)
    {
        url = null!;
        var s = (input ?? string.Empty).Trim();
        if (s.Length == 0) { error = "Test URL is required."; return false; }
        if (s.Length > 500) { error = "Test URL is too long (500 characters max)."; return false; }
        if (!Uri.TryCreate(s, UriKind.Absolute, out var parsed) || parsed.Scheme is not ("http" or "https"))
        {
            error = "Test URL must be an absolute http:// or https:// address.";
            return false;
        }
        if (!string.IsNullOrEmpty(parsed.UserInfo)) { error = "Test URL must not carry credentials."; return false; }

        var host = parsed.IdnHost.Trim('[', ']');
        if (TryIpLiteral(host, out var ip))
        {
            if (!IsPublicAddress(ip)) { error = "Test URL must point at a public address — the test measures a WAN."; return false; }
        }
        else if (!HostnameRx().IsMatch(host) || !host.Contains('.'))
        {
            error = "Test URL host is not a valid public hostname.";
            return false;
        }

        url = parsed;
        error = null;
        return true;
    }

    public bool IsPublicAddress(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip) || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.IPv6Any) || ip.Equals(IPAddress.Broadcast))
            return false;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return !(b[0] == 0                                   // this network
                     || b[0] == 10                               // RFC 1918
                     || (b[0] == 100 && b[1] is >= 64 and <= 127) // CGNAT
                     || (b[0] == 169 && b[1] == 254)             // link-local
                     || (b[0] == 172 && b[1] is >= 16 and <= 31) // RFC 1918
                     || (b[0] == 192 && b[1] == 168)             // RFC 1918
                     || (b[0] == 192 && b[1] == 0 && b[2] == 0)  // IETF protocol assignments
                     || (b[0] == 198 && b[1] is 18 or 19)        // benchmarking
                     || b[0] >= 224);                            // multicast + reserved
        }

        return !(ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6Multicast || ip.IsIPv6UniqueLocal);
    }

    /// <summary>
    /// Strict IP literal. <c>IPAddress.TryParse</c> accepts shorthand like "1.2.3" (→ 1.2.0.3)
    /// and zone ids ("fe80::1%eth0"); neither is welcome in a command argument.
    /// </summary>
    private static bool TryIpLiteral(string s, out IPAddress ip)
    {
        ip = IPAddress.None;
        if (s.Contains('%')) return false;
        if (!IPAddress.TryParse(s, out var parsed)) return false;
        if (parsed.AddressFamily == AddressFamily.InterNetwork && s.Count(c => c == '.') != 3) return false;
        ip = parsed;
        return true;
    }
}
