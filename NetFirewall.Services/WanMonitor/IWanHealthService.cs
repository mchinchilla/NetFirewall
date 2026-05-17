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
}
