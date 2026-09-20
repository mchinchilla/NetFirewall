using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NetFirewall.Services.Diagnostics.Capture;
using NetFirewall.Services.Settings;
using Npgsql;

namespace NetFirewall.Services.Diagnostics;

/// <summary>
/// Diagnostics retention: prunes <c>diag_runs</c> rows older than
/// <c>diagnostics.history_retention_days</c> and capture pcaps older than
/// <c>diagnostics.capture_retention_hours</c>.
/// Same shape as <see cref="Firewall.AuditPrunerService"/>: hosted in the daemon,
/// one pass 30 s after start and then every 6 h; retention &lt;= 0 means keep forever.
/// </summary>
public sealed class DiagRunPrunerService : BackgroundService
{
    public const string RetentionKey = "diagnostics.history_retention_days";
    public const string CaptureRetentionKey = "diagnostics.capture_retention_hours";
    private static readonly TimeSpan PruneInterval = TimeSpan.FromHours(6);

    private readonly NpgsqlDataSource _ds;
    private readonly IAppSettingsService _settings;
    private readonly ICaptureStore _captures;
    private readonly ILogger<DiagRunPrunerService> _logger;

    public DiagRunPrunerService(NpgsqlDataSource ds, IAppSettingsService settings, ICaptureStore captures, ILogger<DiagRunPrunerService> logger)
    {
        _ds = ds;
        _settings = settings;
        _captures = captures;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken); }
        catch (OperationCanceledException) { return; }

        using var timer = new PeriodicTimer(PruneInterval);
        do
        {
            try
            {
                await PruneOnceAsync(stoppingToken);
                await PruneCapturesAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Diagnostics history pruner pass failed; will retry in {Interval}", PruneInterval);
            }
        } while (await SafeWaitAsync(timer, stoppingToken));

        _logger.LogInformation("Diagnostics history pruner stopped");
    }

    private async Task PruneOnceAsync(CancellationToken ct)
    {
        var days = await _settings.GetIntAsync(RetentionKey, ct);
        if (days <= 0)
        {
            _logger.LogDebug("{Key} <= 0 — diagnostics history pruner skipped (keep forever)", RetentionKey);
            return;
        }

        var cutoff = DateTime.UtcNow - TimeSpan.FromDays(days);
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("DELETE FROM diag_runs WHERE started_at < @cutoff", conn);
        cmd.Parameters.AddWithValue("cutoff", cutoff);

        try
        {
            var deleted = await cmd.ExecuteNonQueryAsync(ct);
            if (deleted > 0)
                _logger.LogInformation("Diagnostics history pruner removed {Count} diag_runs rows older than {Cutoff} ({Days}d retention)",
                    deleted, cutoff, days);
        }
        catch (PostgresException ex) when (ex.SqlState == "42P01")
        {
            _logger.LogWarning("diag_runs missing (migration 00041 not applied) — pruner skipped this pass.");
        }
    }

    private async Task PruneCapturesAsync(CancellationToken ct)
    {
        var hours = await _settings.GetIntAsync(CaptureRetentionKey, ct);
        if (hours <= 0) return;   // keep forever, on purpose
        _captures.PurgeOlderThan(TimeSpan.FromHours(hours));
    }

    private static async Task<bool> SafeWaitAsync(PeriodicTimer timer, CancellationToken ct)
    {
        try { return await timer.WaitForNextTickAsync(ct); }
        catch (OperationCanceledException) { return false; }
    }
}
