using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics;

/// <summary>
/// ICMP probes steered the way the firewall actually routes: by fwmark (the
/// policy-routing tables — WAN1 0x100, WAN2 0x200, tunnel 0x500…) or by
/// interface. All inputs are pre-validated literals; hostnames are resolved
/// in-process so the binaries only ever see IP addresses.
/// </summary>
public interface IPingProbeService
{
    /// <summary>Resolve a hostname to its first IPv4 (else IPv6) address; a literal is returned as-is. Null when unresolvable.</summary>
    Task<string?> ResolveAsync(string host, CancellationToken ct = default);

    /// <param name="fwmark">0 = none. Otherwise <c>ping -m</c> (needs CAP_NET_ADMIN — the daemon has it).</param>
    Task<PingResult> PingAsync(string targetIp, string? iface, long fwmark, int count, int timeoutSec, CancellationToken ct = default);

    /// <summary>
    /// Hop list. Without a mark: <c>traceroute -n -q 1</c>. With a mark: traceroute has no
    /// fwmark option, so hops are discovered with <c>ping -t &lt;ttl&gt; -m &lt;mark&gt;</c> — one
    /// probe per hop, which is exactly the path a marked packet takes.
    /// </summary>
    Task<TracerouteResult> TracerouteAsync(string targetIp, string? iface, long fwmark, int maxHops, int timeoutSec, CancellationToken ct = default);
}
