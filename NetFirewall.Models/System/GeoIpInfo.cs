namespace NetFirewall.Models.System;

/// <summary>
/// Geolocation + ASN/org enrichment for a single IP, sourced on-demand from
/// ip.guide. Used by the login system-info card and the post-login "connecting
/// from" card. Distinct from the background <c>ip_asn_cache</c> enrichment
/// (which is fire-and-forget and drops timezone / lat-lon): this carries the
/// full shape the UI shows and is fetched synchronously per request.
/// </summary>
/// <param name="Ip">The IP that was enriched (the client's public IP, or the
/// firewall's own WAN egress when the client is on the LAN).</param>
/// <param name="ForSelf">True when this describes the firewall's own egress IP
/// (client was private/LAN) rather than the client's own public IP. Lets the UI
/// label it as the uplink instead of "your location".</param>
/// <param name="Ok">False when the lookup failed or was disabled — the UI then
/// renders muted placeholders ("—") instead of breaking.</param>
public sealed record GeoIpInfo(
    string? Ip,
    string? City,
    string? Country,        // ISO-3166 alpha-2, e.g. "HN"
    string? CountryName,    // e.g. "Honduras"
    string? Asn,            // e.g. "AS273189"
    string? Org,            // e.g. "Cogent Communications"
    string? Timezone,       // IANA tz, e.g. "America/Tegucigalpa"
    double? Latitude,
    double? Longitude,
    bool ForSelf,
    bool Ok)
{
    /// <summary>A failed/empty result for the given IP — renders as placeholders.</summary>
    public static GeoIpInfo Unavailable(string? ip, bool forSelf) =>
        new(ip, null, null, null, null, null, null, null, null, forSelf, Ok: false);
}
