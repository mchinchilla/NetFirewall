namespace NetFirewall.Services.Dhcp;

/// <summary>
/// Per-client packet rate limit for the DHCP receive loop (before the bounded queue), so one
/// client stuck in a DISCOVER loop — or flooding on purpose — can't push everyone else's packets
/// out of the drop-oldest queue. Keyed by chaddr. Memory is fixed; a flood of spoofed MACs only
/// evicts entries (it fails open), it never grows the table. Config: <c>Dhcp:RateLimit</c>.
/// </summary>
public interface IDhcpRateLimiter
{
    /// <summary>True = process the packet; false = over the client's budget, drop it.</summary>
    bool TryAcquire(ReadOnlySpan<byte> mac);

    /// <summary>Packets refused since start (for the stats line).</summary>
    long Dropped { get; }
}
