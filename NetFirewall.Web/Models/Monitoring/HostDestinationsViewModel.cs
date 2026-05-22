namespace NetFirewall.Web.Models.Monitoring;

/// <summary>
/// View model for the per-host destination drill-down, rendered when a row in
/// the "Top hosts" panel is expanded. Lists the destinations a host talked to,
/// enriched with ASN/org so "Amazon" is distinguishable from an unknown provider.
/// </summary>
public sealed class HostDestinationsViewModel
{
    /// <summary>The host being drilled into (LAN source IP).</summary>
    public string SrcIp { get; init; } = "";

    /// <summary>Optional friendly hostname echoed from the row.</summary>
    public string? Hostname { get; init; }

    /// <summary>The selected window token, echoed so the partial can show it.</summary>
    public string Range { get; init; } = "24h";

    public IReadOnlyList<HostDestinationRow> Destinations { get; init; } = [];

    /// <summary>Set when the lookup failed, so the partial shows an inline error.</summary>
    public string? Error { get; init; }
}

/// <summary>One destination row. <see cref="IsOthers"/> marks the rollup bucket.</summary>
public sealed class HostDestinationRow
{
    public string? DstIp { get; init; }      // null/empty = the "others" rollup
    public string? Asn { get; init; }
    public string? Org { get; init; }
    public string? Country { get; init; }
    public long BytesIn { get; init; }       // upload (LAN→outside)
    public long BytesOut { get; init; }      // download (outside→LAN)
    public int FlowCount { get; init; }

    public bool IsOthers => string.IsNullOrEmpty(DstIp);
    public long TotalBytes => BytesIn + BytesOut;
}
