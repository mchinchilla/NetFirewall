namespace NetFirewall.Services.Dhcp;

/// <summary>
/// Lightweight wrapper over Postgres <c>NOTIFY</c> for invalidating the
/// DhcpServer's in-process subnet cache when the Web mutates the catalog.
/// Without this, edits made via the UI take up to 5 minutes (cache TTL) to
/// reach DHCP responses.
///
/// Channel names are constants on this interface so producer + consumer
/// can't drift.
/// </summary>
public interface IDhcpCacheNotifier
{
    public const string SubnetChannel = "dhcp_cache_invalidate";

    /// <summary>Send a NOTIFY on the subnet/pool/exclusion channel.</summary>
    Task NotifySubnetChangedAsync(string reason, CancellationToken ct = default);
}
