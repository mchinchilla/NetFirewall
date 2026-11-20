using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using RepoDb.Attributes;

namespace NetFirewall.Models.Dhcp;

/// <summary>
/// An operator-defined DHCP option (table dhcp_custom_options): VoIP provisioning (66/150),
/// access-point controllers (43/138), vendor options, … Sent to the clients of its scope.
/// Precedence for the same code: host (a reservation) &gt; class &gt; subnet &gt; global.
/// Options the server already sets itself (router, DNS, lease times…) are never overridden.
/// </summary>
public class DhcpCustomOption
{
    [Map("id")] public Guid Id { get; set; }
    /// <summary><see cref="DhcpOptionScopes"/>.</summary>
    [Map("scope_type")] public string ScopeType { get; set; } = DhcpOptionScopes.Global;
    /// <summary>Subnet / class / reservation id; null for global.</summary>
    [Map("scope_id")] public Guid? ScopeId { get; set; }
    [Map("option_code")] public short OptionCode { get; set; }
    [Map("option_name")] public string? OptionName { get; set; }
    /// <summary>The encoded option payload, exactly as sent.</summary>
    [Map("option_value")] public byte[] OptionValue { get; set; } = [];
    /// <summary><see cref="DhcpOptionFormats"/> — how the operator typed it (for display/edit).</summary>
    [Map("option_format")] public string? OptionFormat { get; set; }
    [Map("created_at")] public DateTime CreatedAt { get; set; }
}

public static class DhcpOptionScopes
{
    public const string Global = "global";
    public const string Subnet = "subnet";
    public const string Class = "class";
    public const string Host = "host";
    public static readonly string[] All = [Global, Subnet, Class, Host];
}

public static class DhcpOptionFormats
{
    public const string Ip = "ip";
    public const string IpList = "ip_list";
    public const string Text = "string";
    public const string UInt8 = "uint8";
    public const string UInt16 = "uint16";
    public const string UInt32 = "uint32";
    public const string Bool = "bool";
    public const string Hex = "hex";
    public static readonly string[] All = [Ip, IpList, Text, UInt8, UInt16, UInt32, Bool, Hex];
}

/// <summary>Typed text → option payload, validated. Pure.</summary>
public static class DhcpOptionEncoder
{
    /// <summary>
    /// Codes the protocol itself owns: setting them by hand would corrupt the exchange
    /// (message type, server id, lease times, PRL, client id, relay info, overload, pad/end).
    /// </summary>
    public static readonly HashSet<int> Reserved = [0, 50, 51, 52, 53, 54, 55, 57, 58, 59, 61, 82, 255];

    public static bool TryEncode(int code, string format, string? text, out byte[] data, out string? error)
    {
        data = [];
        error = null;
        if (code is < 1 or > 254) { error = "Option code must be 1–254."; return false; }
        if (Reserved.Contains(code)) { error = $"Option {code} is managed by the DHCP protocol and can't be set by hand."; return false; }
        var value = (text ?? string.Empty).Trim();
        if (value.Length == 0) { error = "A value is required."; return false; }

        switch (format)
        {
            case DhcpOptionFormats.Ip or DhcpOptionFormats.IpList:
            {
                var parts = value.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                if (format == DhcpOptionFormats.Ip && parts.Length != 1) { error = "One IPv4 address."; return false; }
                var bytes = new List<byte>(parts.Length * 4);
                foreach (var p in parts)
                {
                    // Dotted quad only: IPAddress.TryParse also takes inet_aton shorthands ("10.0.0" → 10.0.0.0).
                    if (p.Count(c => c == '.') != 3 || !IPAddress.TryParse(p, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
                    { error = $"'{p}' is not an IPv4 address."; return false; }
                    bytes.AddRange(ip.GetAddressBytes());
                }
                data = bytes.ToArray();
                break;
            }
            case DhcpOptionFormats.Text:
                if (value.Any(c => c > 0x7E || c < 0x20)) { error = "Text must be printable ASCII."; return false; }
                data = global::System.Text.Encoding.ASCII.GetBytes(value);
                break;
            case DhcpOptionFormats.UInt8:
                if (!byte.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var u8)) { error = "A number 0–255."; return false; }
                data = [u8];
                break;
            case DhcpOptionFormats.UInt16:
                if (!ushort.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var u16)) { error = "A number 0–65535."; return false; }
                data = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(data, u16);
                break;
            case DhcpOptionFormats.UInt32:
                if (!uint.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var u32)) { error = "A number 0–4294967295."; return false; }
                data = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(data, u32);
                break;
            case DhcpOptionFormats.Bool:
                data = value.ToLowerInvariant() switch { "true" or "1" or "yes" or "on" => [1], "false" or "0" or "no" or "off" => [0], _ => [] };
                if (data.Length == 0) { error = "true or false."; return false; }
                break;
            case DhcpOptionFormats.Hex:
                var hex = value.Replace(":", "").Replace(" ", "").Replace("-", "");
                if (hex.Length % 2 != 0) { error = "Hex needs an even number of digits."; return false; }
                try { data = Convert.FromHexString(hex); }
                catch (FormatException) { error = "Hex digits only (0-9, a-f)."; return false; }
                break;
            default:
                error = $"Unknown format '{format}'."; return false;
        }

        if (data.Length is 0 or > 255) { error = "The encoded value must be 1–255 bytes."; data = []; return false; }
        return true;
    }

    /// <summary>The payload back as the text the operator typed (for the edit form).</summary>
    public static string Decode(string? format, byte[] data) => format switch
    {
        DhcpOptionFormats.Ip or DhcpOptionFormats.IpList when data.Length % 4 == 0 =>
            string.Join(", ", Enumerable.Range(0, data.Length / 4).Select(i => new IPAddress(data.AsSpan(i * 4, 4)).ToString())),
        DhcpOptionFormats.Text => global::System.Text.Encoding.ASCII.GetString(data),
        DhcpOptionFormats.UInt8 when data.Length == 1 => data[0].ToString(CultureInfo.InvariantCulture),
        DhcpOptionFormats.UInt16 when data.Length == 2 => BinaryPrimitives.ReadUInt16BigEndian(data).ToString(CultureInfo.InvariantCulture),
        DhcpOptionFormats.UInt32 when data.Length == 4 => BinaryPrimitives.ReadUInt32BigEndian(data).ToString(CultureInfo.InvariantCulture),
        DhcpOptionFormats.Bool when data.Length == 1 => data[0] != 0 ? "true" : "false",
        _ => Convert.ToHexString(data).ToLowerInvariant(),
    };
}
