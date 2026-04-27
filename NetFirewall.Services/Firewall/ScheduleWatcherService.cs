using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace NetFirewall.Services.Firewall;

/// <summary>
/// Background service that ticks every minute, computes the set of currently-
/// active schedule ids, and triggers an nft re-apply when that set changed
/// since the last tick. Hosted in the daemon (needs CAP_NET_ADMIN to actually
/// load the new ruleset).
///
/// Cheap by design: a tick reads <c>fw_schedules</c> once and runs an
/// in-process predicate per schedule. Apply only happens on transitions, so
/// most ticks are no-ops even with dozens of schedules.
/// </summary>
public sealed class ScheduleWatcherService : BackgroundService
{
    private static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(60);

    private readonly IServiceProvider _services;
    private readonly ILogger<ScheduleWatcherService> _logger;

    private HashSet<Guid> _lastActive = new();

    public ScheduleWatcherService(IServiceProvider services, ILogger<ScheduleWatcherService> logger)
    {
        _services = services;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Wait a beat so the daemon's DB pool warms up before the first tick.
        try { await Task.Delay(TimeSpan.FromSeconds(15), stoppingToken); }
        catch (OperationCanceledException) { return; }

        // Seed the "last active" set so we don't re-apply on the very first
        // tick just because we don't know the prior state.
        _lastActive = await ComputeActiveAsync(stoppingToken);
        _logger.LogInformation("Schedule watcher started — initial active set has {Count} schedule(s)", _lastActive.Count);

        using var timer = new PeriodicTimer(TickInterval);
        while (!stoppingToken.IsCancellationRequested && await SafeWaitAsync(timer, stoppingToken))
        {
            try
            {
                var current = await ComputeActiveAsync(stoppingToken);
                if (!current.SetEquals(_lastActive))
                {
                    _logger.LogInformation(
                        "Schedule transition: was [{Before}] now [{After}] — re-applying firewall",
                        string.Join(",", _lastActive),
                        string.Join(",", current));
                    await ReApplyAsync(stoppingToken);
                    _lastActive = current;
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Schedule watcher tick failed; will retry next minute");
            }
        }

        _logger.LogInformation("Schedule watcher stopped");
    }

    private async Task<HashSet<Guid>> ComputeActiveAsync(CancellationToken ct)
    {
        using var scope = _services.CreateScope();
        var schedules = scope.ServiceProvider.GetRequiredService<IScheduleService>();
        var nowUtc = DateTimeOffset.UtcNow;
        var all = await schedules.GetAllAsync(ct);
        return all.Where(s => s.IsActiveAt(nowUtc)).Select(s => s.Id).ToHashSet();
    }

    private async Task ReApplyAsync(CancellationToken ct)
    {
        using var scope = _services.CreateScope();
        var nft = scope.ServiceProvider.GetRequiredService<INftApplyService>();
        var result = await nft.ApplyConfigurationAsync(ct);
        if (!result.Success)
            _logger.LogWarning("Schedule-triggered nft apply failed (exit {Exit}): {Err}",
                result.ExitCode, result.Error);
    }

    private static async Task<bool> SafeWaitAsync(PeriodicTimer timer, CancellationToken ct)
    {
        try { return await timer.WaitForNextTickAsync(ct); }
        catch (OperationCanceledException) { return false; }
    }
}
