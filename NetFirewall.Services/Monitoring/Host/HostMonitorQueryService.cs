using Microsoft.Extensions.Hosting;
using NetFirewall.Models;

namespace NetFirewall.Services.Monitoring.Host;

/// <summary>Shapes the in-memory host monitor into one window for the UI.</summary>
public interface IHostMonitorQueryService
{
    /// <summary>
    /// The monitor over <paramref name="windowSeconds"/> (1, 5, 15 or 60 minutes;
    /// anything else falls back to one minute). Fails only when this machine has
    /// no <c>/proc</c> or the monitor is disabled.
    /// </summary>
    Task<ServiceResponse<HostMonitorView>> GetAsync(int? windowSeconds, CancellationToken ct = default);
}

public sealed class HostMonitorQueryService(IHostMonitor monitor, TimeProvider time) : IHostMonitorQueryService
{
    /// <summary>The programs shown: the ones burning the most CPU.</summary>
    public const int TopProcesses = 8;

    public Task<ServiceResponse<HostMonitorView>> GetAsync(int? windowSeconds, CancellationToken ct = default)
    {
        var window = HostWindows.Clean(windowSeconds);
        var now = time.GetUtcNow();

        // One second of slack: the window ends at the last sample, not the wall clock.
        if (monitor.Snapshot(now.AddSeconds(-window - 1)) is not { } state)
        {
            return Task.FromResult(ServiceResponse<HostMonitorView>.Fail(
                "The host monitor needs /proc — it only runs on Linux (or HostMonitor:Enabled is false)."));
        }

        HostSample? current = state.Samples.Count > 0 ? state.Samples[^1] : null;
        var end = current?.Time ?? now;
        var span = TimeSpan.FromSeconds(window);

        var view = new HostMonitorView(
            state.Identity,
            current,
            window,
            HostTimeline.Columns(state.Samples, end, span, HostTimeline.WideColumns),
            HostTimeline.Columns(state.Samples, end, span, HostTimeline.NarrowColumns),
            [.. state.Processes.OrderByDescending(p => p.CpuShare).ThenBy(p => p.Name, StringComparer.Ordinal).Take(TopProcesses)],
            state.Filesystems,
            state.Cost,
            now);

        return Task.FromResult(ServiceResponse<HostMonitorView>.Ok(view));
    }
}

/// <summary>
/// Starts the host monitor's sampling. Runs even when nobody is looking: that's
/// what lets the page show the last hour the moment it opens, and a sample costs
/// microseconds.
/// </summary>
public sealed class HostMonitorHostedService(IHostMetricsSampler sampler) : BackgroundService
{
    protected override Task ExecuteAsync(CancellationToken stoppingToken) => sampler.RunAsync(stoppingToken);
}
