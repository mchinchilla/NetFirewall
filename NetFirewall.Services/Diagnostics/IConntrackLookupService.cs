using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics;

/// <summary>
/// Filtered <c>conntrack -L</c> lookup. The reply tuple is the payoff: after NAT the
/// reply's destination is the address we masqueraded to, which tells you whether a
/// LAN flow left through a WAN or through the tunnel without any packet capture.
/// </summary>
public interface IConntrackLookupService
{
    /// <param name="src">IP or IPv4 CIDR (validated).</param>
    /// <param name="dst">IP or IPv4 CIDR (validated).</param>
    /// <param name="proto">tcp | udp | icmp | "" (validated).</param>
    /// <param name="port">Destination port; only applied with tcp/udp.</param>
    Task<ConntrackLookupResult> LookupAsync(string? src, string? dst, string proto, int port, int limit, CancellationToken ct = default);
}
