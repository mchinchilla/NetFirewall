using System.Text;

namespace NetFirewall.Models.Network;

/// <summary>
/// One DNS host label (RFC 1123): a–z, 0–9 and '-', 1–63 chars, no leading/trailing '-'.
/// Shared by the reservation form, the DB CHECK constraint and the lease-name publisher. Pure.
/// </summary>
public static class DnsHostName
{
    public static bool IsValid(string? label) =>
        label is { Length: >= 1 and <= 63 }
        && label[0] != '-' && label[^1] != '-'
        && label.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-');

    /// <summary>
    /// What a DHCP client sent as option 12 turned into a usable label, or null: first label only
    /// ("laptop.corp" → "laptop"), lower-cased, spaces/underscores → '-', other characters dropped
    /// ("Marvin's iPhone" → "marvins-iphone"). Clients send all sorts.
    /// </summary>
    public static string? Sanitize(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw)) return null;
        var first = raw.Trim().Split('.')[0];
        var sb = new StringBuilder(first.Length);
        foreach (var c in first.ToLowerInvariant())
        {
            if (c is >= 'a' and <= 'z' or >= '0' and <= '9') sb.Append(c);
            else if (c is ' ' or '_' or '-') { if (sb.Length > 0 && sb[^1] != '-') sb.Append('-'); }
        }
        var label = sb.ToString().Trim('-');
        if (label.Length > 63) label = label[..63].TrimEnd('-');
        return IsValid(label) ? label : null;
    }
}
