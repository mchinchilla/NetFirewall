using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NetFirewall.Services.Settings;
using Npgsql;

namespace NetFirewall.Services.Firewall;

/// <summary>
/// Background service that prunes <c>fw_audit_log</c> rows older than the
/// retention window configured in <c>audit.retention_days</c>. Runs every
/// 6 hours plus once on startup so a freshly-tuned retention takes effect
/// without waiting a full cycle.
///
/// Retention <= 0 means "keep forever" — the pruner skips the pass and
/// logs once per cycle so you can verify it's intentionally disabled.
///
/// Hosted in the daemon (BackgroundService + DB access; the Web doesn't
/// need to spend cycles on cleanup).
/// </summary>
public sealed class AuditPrunerService : BackgroundService
{
    private static readonly TimeSpan PruneInterval = TimeSpan.FromHours(6);

    private readonly NpgsqlDataSource _ds;
    private readonly IAppSettingsService _settings;
    private readonly ILogger<AuditPrunerService> _logger;

    public AuditPrunerService(
        NpgsqlDataSource ds,
        IAppSettingsService settings,
        ILogger<AuditPrunerService> logger)
    {
        _ds = ds;
        _settings = settings;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Wait a beat so the daemon's DB pool is warm before the first run.
        try { await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken); }
        catch (OperationCanceledException) { return; }

        using var timer = new PeriodicTimer(PruneInterval);
        do
        {
            try
            {
                await PruneOnceAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Audit pruner pass failed; will retry in {Interval}", PruneInterval);
            }
        } while (await SafeWaitAsync(timer, stoppingToken));

        _logger.LogInformation("Audit pruner stopped");
    }

    private async Task PruneOnceAsync(CancellationToken ct)
    {
        var days = await _settings.GetIntAsync("audit.retention_days", ct);
        if (days <= 0)
        {
            _logger.LogDebug("audit.retention_days <= 0 — pruner skipped (keep forever)");
            return;
        }

        var cutoff = DateTime.UtcNow - TimeSpan.FromDays(days);

        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "DELETE FROM fw_audit_log WHERE created_at < @cutoff", conn);
        cmd.Parameters.AddWithValue("cutoff", cutoff);

        try
        {
            var deleted = await cmd.ExecuteNonQueryAsync(ct);
            if (deleted > 0)
                _logger.LogInformation("Audit pruner removed {Count} fw_audit_log rows older than {Cutoff} ({Days}d retention)",
                    deleted, cutoff, days);
            else
                _logger.LogDebug("Audit pruner: 0 rows older than {Cutoff}", cutoff);
        }
        catch (PostgresException ex) when (ex.SqlState == "42P01")
        {
            // fw_audit_log doesn't exist yet — fresh install before migrations.
            _logger.LogWarning("fw_audit_log missing — audit pruner skipped this pass.");
        }
    }

    private static async Task<bool> SafeWaitAsync(PeriodicTimer timer, CancellationToken ct)
    {
        try { return await timer.WaitForNextTickAsync(ct); }
        catch (OperationCanceledException) { return false; }
    }
}
