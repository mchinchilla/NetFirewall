using System.Data;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace NetFirewall.Services.Firewall;

/// <summary>
/// Background service hosted in the daemon (needs CAP_NET_ADMIN). Rebuilds
/// nftables whenever the set of currently-active scheduled rules would
/// change: at daemon start (so a restart after a missed edge is not stale),
/// at each schedule Start/End, and when a schedule or scheduled filter rule
/// is written (Postgres NOTIFY).
///
/// Generation still snapshots "is this rule live right now" — invert drops
/// for an allow-during policy are in the ruleset outside the window and
/// gone inside it. Sleeping until the next edge (plus a 15s safety cap)
/// is what makes the programmed hour actually take effect.
/// </summary>
public sealed class ScheduleWatcherService : BackgroundService
{
    private static readonly TimeSpan StartupDelay = TimeSpan.FromSeconds(2);

    private readonly IServiceProvider _services;
    private readonly ILogger<ScheduleWatcherService> _logger;

    private string? _lastFingerprint;
    private NpgsqlConnection? _listen;

    public ScheduleWatcherService(IServiceProvider services, ILogger<ScheduleWatcherService> logger)
    {
        _services = services;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { await Task.Delay(StartupDelay, stoppingToken); }
        catch (OperationCanceledException) { return; }

        // Always apply on start: seeding without apply left nft stale after
        // a restart that missed a transition (or a time-policy saved while
        // the daemon was down).
        await SafeTickAsync(forceApply: true, stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var delay = await ComputeDelayAsync(stoppingToken);
                await WaitForWakeAsync(delay, stoppingToken);
                await SafeTickAsync(forceApply: false, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Schedule watcher tick failed; retrying shortly");
                try { await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken); }
                catch (OperationCanceledException) { break; }
            }
        }

        await DisposeListenAsync();
        _logger.LogInformation("Schedule watcher stopped");
    }

    /// <summary>
    /// Compare the live schedule/rule fingerprint to the last apply and
    /// rebuild nft when it changed (or when <paramref name="forceApply"/>).
    /// Internal so tests can drive one evaluation without the host loop.
    /// </summary>
    internal async Task<bool> TickAsync(bool forceApply, CancellationToken ct)
    {
        using var scope = _services.CreateScope();
        var scheduleSvc = scope.ServiceProvider.GetRequiredService<IScheduleService>();
        var firewall = scope.ServiceProvider.GetRequiredService<IFirewallService>();
        var schedules = await scheduleSvc.GetAllAsync(ct);
        var rules = await firewall.GetFilterRulesAsync(null, ct);
        var now = DateTimeOffset.UtcNow;
        var fp = ScheduleApplyPlanner.Fingerprint(schedules, rules, now);

        if (!forceApply && fp == _lastFingerprint)
            return false;

        _logger.LogInformation(
            "Schedule-triggered nft apply ({Reason}) — {Count} scheduled rule(s)",
            forceApply && _lastFingerprint is null ? "startup" : "transition",
            rules.Count(r => r.Enabled && r.ScheduleId.HasValue));

        await ReApplyAsync(scope.ServiceProvider, ct);
        _lastFingerprint = fp;
        return true;
    }

    private async Task SafeTickAsync(bool forceApply, CancellationToken ct)
    {
        try
        {
            await TickAsync(forceApply, ct);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Schedule watcher apply failed; will retry");
        }
    }

    private async Task<TimeSpan> ComputeDelayAsync(CancellationToken ct)
    {
        using var scope = _services.CreateScope();
        var scheduleSvc = scope.ServiceProvider.GetRequiredService<IScheduleService>();
        var firewall = scope.ServiceProvider.GetRequiredService<IFirewallService>();
        var schedules = await scheduleSvc.GetAllAsync(ct);
        var rules = await firewall.GetFilterRulesAsync(null, ct);
        var now = DateTimeOffset.UtcNow;
        var edge = ScheduleApplyPlanner.NextEdge(schedules, rules, now);
        var delay = ScheduleApplyPlanner.DelayUntil(now, edge);
        if (edge is { } t && delay < ScheduleApplyPlanner.MaxTick)
            _logger.LogDebug("Schedule watcher sleeping {Delay} until next edge {Edge:o}", delay, t);
        return delay;
    }

    private async Task WaitForWakeAsync(TimeSpan delay, CancellationToken ct)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linked.CancelAfter(delay);
        try
        {
            try { await EnsureListenAsync(linked.Token); }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Schedule watcher LISTEN unavailable; falling back to timer");
                await Task.Delay(delay, ct);
                return;
            }

            if (_listen is null)
            {
                await Task.Delay(delay, ct);
                return;
            }

            await _listen.WaitAsync(linked.Token);
            _logger.LogDebug("Schedule watcher woken by NOTIFY");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // Timer elapsed — next clock edge or the safety cap.
        }
        catch (NpgsqlException ex)
        {
            _logger.LogDebug(ex, "Schedule watcher LISTEN dropped; will reconnect");
            await DisposeListenAsync();
        }
    }

    private async Task EnsureListenAsync(CancellationToken ct)
    {
        if (_listen is { State: ConnectionState.Open }) return;
        await DisposeListenAsync();

        var ds = _services.GetService<NpgsqlDataSource>();
        if (ds is null) return;

        var conn = await ds.OpenConnectionAsync(ct);
        await using (var cmd = new NpgsqlCommand($"LISTEN {ScheduleApplyNotify.Channel}", conn))
            await cmd.ExecuteNonQueryAsync(ct);

        _listen = conn;
        _logger.LogInformation("Schedule watcher listening on {Channel}", ScheduleApplyNotify.Channel);
    }

    private async Task DisposeListenAsync()
    {
        if (_listen is null) return;
        try { await _listen.DisposeAsync(); }
        catch { /* already gone */ }
        _listen = null;
    }

    private async Task ReApplyAsync(IServiceProvider sp, CancellationToken ct)
    {
        var nft = sp.GetRequiredService<INftApplyService>();
        var result = await nft.ApplyConfigurationAsync(ct);
        if (!result.Success)
            _logger.LogWarning("Schedule-triggered nft apply failed (exit {Exit}): {Err}",
                result.ExitCode, result.Error);
    }
}
