using NetFirewall.Models.WanMonitor;

namespace NetFirewall.Services.WanMonitor;

/// <summary>
/// CRUD + state I/O for the WAN health subsystem. Used by both the daemon's
/// background monitor and the Web's dashboard endpoints.
/// </summary>
public interface IWanHealthService
{
    /// <summary>All enabled health configs joined with interface names. Used by the monitor loop.</summary>
    Task<IReadOnlyList<WanHealthConfig>> GetConfigsAsync(CancellationToken ct = default);

    /// <summary>Current state row per interface (joined with name+role). Empty if no probes have run yet.</summary>
    Task<IReadOnlyList<WanHealthState>> GetStateAsync(CancellationToken ct = default);

    /// <summary>UPSERT the state row after a probe cycle.</summary>
    Task UpsertStateAsync(WanHealthState state, CancellationToken ct = default);

    /// <summary>Append a transition event (down/up/failover/demoted).</summary>
    Task RecordEventAsync(Guid interfaceId, string eventType, string? detailJson, CancellationToken ct = default);

    /// <summary>Last N events, newest first. Powers the dashboard's failover history strip.</summary>
    Task<IReadOnlyList<WanHealthEvent>> RecentEventsAsync(int limit = 20, CancellationToken ct = default);

    // ───────────── failover control (active WAN + sticky override) ─────────────

    /// <summary>The singleton control row (active WAN + manual override), with names. Never null.</summary>
    Task<WanFailoverControl> GetControlAsync(CancellationToken ct = default);

    /// <summary>Set or clear the sticky manual override. Pass null to return to auto mode.</summary>
    Task SetOverrideAsync(Guid? interfaceId, string? setBy, CancellationToken ct = default);

    /// <summary>Record which interface the monitor just made the active default route.</summary>
    Task SetActiveAsync(Guid interfaceId, CancellationToken ct = default);

    // ───────────── config CRUD (read/write the per-WAN probe config) ─────────────

    /// <summary>Every config row (enabled or not), joined with interface names. For the admin UI.</summary>
    Task<IReadOnlyList<WanHealthConfig>> GetAllConfigsAsync(CancellationToken ct = default);

    /// <summary>Insert or update a config row keyed by interface_id.</summary>
    Task UpsertConfigAsync(WanHealthConfig config, CancellationToken ct = default);
}
