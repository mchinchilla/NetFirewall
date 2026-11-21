namespace NetFirewall.Services.Dhcp;

/// <summary>
/// In-memory view of <c>dhcp_mac_blocklist</c> for the DHCP server (singleton). Dropped by the
/// <c>blocklist.changed</c> NOTIFY (migration 00053 → DhcpCacheRefreshListener).
/// </summary>
public interface IDhcpBlocklistCache
{
    /// <summary>True when <paramref name="mac"/> (any separator/case) must never be answered.</summary>
    ValueTask<bool> IsBlockedAsync(string mac, CancellationToken ct = default);

    void Invalidate();
}
