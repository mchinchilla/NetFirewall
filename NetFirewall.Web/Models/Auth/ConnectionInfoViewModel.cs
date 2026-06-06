using NetFirewall.Models.System;

namespace NetFirewall.Web.Models.Auth;

/// <summary>
/// Backs the post-login "Connecting from" card in the account dropdown. Carries
/// the client's real (possibly-LAN) IP for display, the GeoIP enrichment (which
/// describes the firewall's egress when the client is on the LAN), and process
/// uptime.
/// </summary>
public sealed record ConnectionInfoViewModel(
    string ClientIp,
    GeoIpInfo Geo,
    DateTimeOffset StartedAt,
    TimeSpan Uptime);
