namespace NetFirewall.Services.Dhcp;

/// <summary>
/// An immutable in-memory copy of a small table for the DHCP hot path: loaded on first use,
/// dropped by a NOTIFY (<see cref="Invalidate"/>, wired in DhcpCacheRefreshListener) and, as a
/// safety net for a missed notify, reloaded after <see cref="MaxAge"/>. One load at a time;
/// readers never block once a snapshot exists and is fresh.
/// </summary>
public abstract class NotifiedSnapshotCache<TSnapshot>(TimeProvider? time = null) where TSnapshot : class
{
    /// <summary>Reload even without a NOTIFY after this long (a dropped LISTEN connection).</summary>
    public static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(5);

    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly SemaphoreSlim _load = new(1, 1);
    private volatile Entry? _entry;

    private sealed record Entry(TSnapshot Snapshot, DateTimeOffset LoadedAt);

    public void Invalidate() => _entry = null;

    protected abstract Task<TSnapshot> LoadAsync(CancellationToken ct);

    protected async ValueTask<TSnapshot> CurrentAsync(CancellationToken ct)
    {
        var entry = _entry;
        if (entry is not null && _time.GetUtcNow() - entry.LoadedAt < MaxAge) return entry.Snapshot;

        await _load.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            entry = _entry;
            if (entry is not null && _time.GetUtcNow() - entry.LoadedAt < MaxAge) return entry.Snapshot;
            var snapshot = await LoadAsync(ct).ConfigureAwait(false);
            _entry = new Entry(snapshot, _time.GetUtcNow());
            return snapshot;
        }
        finally
        {
            _load.Release();
        }
    }
}
