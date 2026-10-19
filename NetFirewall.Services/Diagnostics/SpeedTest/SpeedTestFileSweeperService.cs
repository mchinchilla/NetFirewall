using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace NetFirewall.Services.Diagnostics.SpeedTest;

/// <summary>
/// Deletes kept speed-test files when they expire. At startup it also removes
/// <c>.part</c> files a crash left behind (no test can be running yet); after
/// that it sweeps every 15 minutes. The store already refuses expired files, so
/// the link dies on time even between sweeps — this reclaims the disk.
/// </summary>
public sealed class SpeedTestFileSweeperService : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromMinutes(15);

    private readonly ISpeedTestStore _store;
    private readonly ILogger<SpeedTestFileSweeperService> _logger;

    public SpeedTestFileSweeperService(ISpeedTestStore store, ILogger<SpeedTestFileSweeperService> logger)
    {
        _store = store;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await SweepAsync(includeInProgress: true, stoppingToken);

        using var timer = new PeriodicTimer(Interval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
                await SweepAsync(includeInProgress: false, stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }

    private async Task SweepAsync(bool includeInProgress, CancellationToken ct)
    {
        try { await _store.SweepAsync(includeInProgress, ct); }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch (Exception ex) { _logger.LogWarning(ex, "Speed-test file sweep failed; will retry in {Interval}", Interval); }
    }
}
