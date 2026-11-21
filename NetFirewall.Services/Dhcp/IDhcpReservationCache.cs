using System.Net;

namespace NetFirewall.Services.Dhcp;

/// <summary>
/// In-memory view of <c>dhcp_mac_reservations</c> for the DHCP hot path (a singleton in the
/// DHCP server). Loaded on first use, dropped on the <c>reservation.changed</c> NOTIFY
/// (migration 00044 → DhcpCacheRefreshListener) and, as a safety net for a missed notify,
/// reloaded after <see cref="DhcpReservationCache.MaxAge"/>.
/// </summary>
public interface IDhcpReservationCache
{
    /// <summary>The IP reserved for <paramref name="mac"/> (any separator/case), or null.</summary>
    ValueTask<IPAddress?> GetReservedIpAsync(string mac, CancellationToken ct = default);

    /// <summary>The reservation's own lease time in seconds (migration 00051), or null = the subnet's default.</summary>
    ValueTask<int?> GetLeaseTimeAsync(string mac, CancellationToken ct = default);

    /// <summary>The MAC (lower-case, colon form) that owns the reserved <paramref name="ip"/>, or null.</summary>
    ValueTask<string?> GetOwnerMacAsync(IPAddress ip, CancellationToken ct = default);

    void Invalidate();
}
