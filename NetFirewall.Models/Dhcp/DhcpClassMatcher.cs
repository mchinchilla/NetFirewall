namespace NetFirewall.Models.Dhcp;

/// <summary>
/// Does a request belong to a client class? Every match type the class form offers works
/// (only vendor_class, mac_prefix and hostname used to — the other five silently never matched).
/// Text types are case-insensitive substring matches; binary ones (client id, relay info,
/// generic option) match on hex, separators ignored. Pure.
/// </summary>
public static class DhcpClassMatcher
{
    public static bool Matches(DhcpRequest request, DhcpClass dhcpClass)
    {
        var want = dhcpClass.MatchValue?.Trim() ?? string.Empty;
        if (want.Length == 0) return false;
        return dhcpClass.MatchType switch
        {
            DhcpClassMatchTypes.VendorClass => Contains(request.VendorClassIdentifier, want),
            DhcpClassMatchTypes.UserClass => Contains(request.UserClass, want),
            DhcpClassMatchTypes.Hostname => Contains(request.Hostname, want),
            DhcpClassMatchTypes.MacPrefix => Hex(request.ClientMac).StartsWith(Hex(want), StringComparison.Ordinal),
            DhcpClassMatchTypes.HardwareType => byte.TryParse(want, out var ht) && request.HType == ht,
            DhcpClassMatchTypes.ClientId => request.ClientIdentifier is { } cid && Convert.ToHexString(cid).Contains(Hex(want), StringComparison.Ordinal),
            DhcpClassMatchTypes.RelayAgent => request.RelayAgentInformation is { } rai && MatchesBinary(rai, want),
            DhcpClassMatchTypes.Option => MatchesGenericOption(request, want),
            _ => false,
        };
    }

    private static bool Contains(string? haystack, string needle) =>
        haystack?.Contains(needle, StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>Upper-case hex digits only ("aa:bb-CC" → "AABBCC").</summary>
    private static string Hex(string? s) =>
        string.Concat((s ?? string.Empty).Where(Uri.IsHexDigit)).ToUpperInvariant();

    /// <summary>Hex in the payload, or the text as ASCII in it (circuit-ids are often text).</summary>
    private static bool MatchesBinary(byte[] payload, string want)
    {
        var hex = Hex(want);
        if (hex.Length > 0 && hex.Length == want.Count(c => !char.IsWhiteSpace(c) && c is not (':' or '-'))
            && Convert.ToHexString(payload).Contains(hex, StringComparison.Ordinal))
            return true;
        return global::System.Text.Encoding.ASCII.GetString(payload).Contains(want, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>"code=value", e.g. "60=MSFT" or "93=0007". Codes the server parses: 12, 60, 61, 77, 82, 93.</summary>
    private static bool MatchesGenericOption(DhcpRequest r, string spec)
    {
        var eq = spec.IndexOf('=');
        if (eq <= 0 || !int.TryParse(spec.AsSpan(0, eq), out var code)) return false;
        var value = spec[(eq + 1)..].Trim();
        return code switch
        {
            12 => Contains(r.Hostname, value),
            60 => Contains(r.VendorClassIdentifier, value),
            77 => Contains(r.UserClass, value),
            61 => r.ClientIdentifier is { } cid && MatchesBinary(cid, value),
            82 => r.RelayAgentInformation is { } rai && MatchesBinary(rai, value),
            93 => r.ClientArchitecture is { } arch && ushort.TryParse(value, out var want) && arch == want,
            _ => false,
        };
    }
}
