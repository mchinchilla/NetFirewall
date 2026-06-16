using NetFirewall.Models.Vpn;

namespace NetFirewall.Services.Vpn;

/// <summary>
/// State + event I/O for the WireGuard health subsystem, plus the active-alert
/// store the UI banner reads. Used by the daemon's VpnHealthMonitorService (writes)
/// and surfaced to the Web over the daemon HTTP API (reads). Mirrors
/// <c>IWanHealthService</c>.
/// </summary>
public interface IVpnHealthService
{
    /// <summary>Current state row per peer, joined with peer + server names. Empty before the first probe.</summary>
    Task<IReadOnlyList<VpnHealthState>> GetStateAsync(CancellationToken ct = default);

    /// <summary>UPSERT the state row after a probe cycle.</summary>
    Task UpsertStateAsync(VpnHealthState state, CancellationToken ct = default);

    /// <summary>Append an up/down transition event.</summary>
    Task RecordEventAsync(Guid serverId, string publicKey, string eventType, string? detailJson, CancellationToken ct = default);

    /// <summary>Last N events, newest first. Powers the dashboard's VPN activity strip.</summary>
    Task<IReadOnlyList<VpnHealthEvent>> RecentEventsAsync(int limit = 20, CancellationToken ct = default);

    // ── active-alert store (banner feed) ──

    /// <summary>Raise (or refresh) an alert keyed by <paramref name="dedupeKey"/>. Idempotent — re-raising an unresolved alert just keeps it active.</summary>
    Task RaiseAlertAsync(SystemAlert alert, CancellationToken ct = default);

    /// <summary>Resolve the alert with this dedupe key, if one is active. No-op otherwise.</summary>
    Task ResolveAlertAsync(string dedupeKey, CancellationToken ct = default);

    /// <summary>All currently-active alerts (unresolved), newest first. Read by the Web's banner.</summary>
    Task<IReadOnlyList<SystemAlert>> ActiveAlertsAsync(CancellationToken ct = default);

    /// <summary>
    /// Last N alerts including resolved ones, newest first. Powers the
    /// notifications dropdown and the full "View all activity" history page.
    /// Cross-subsystem — VPN, WAN failover, and any future source all write to
    /// <c>system_alerts</c>, so this is the unified activity feed.
    /// </summary>
    Task<IReadOnlyList<SystemAlert>> RecentAlertsAsync(int limit = 50, CancellationToken ct = default);
}
