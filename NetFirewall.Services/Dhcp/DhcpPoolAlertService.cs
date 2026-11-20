using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Monitoring;
using Npgsql;

namespace NetFirewall.Services.Dhcp;

/// <summary>A pool's fill level.</summary>
public sealed record PoolUsage(Guid PoolId, string Subnet, string Pool, long Used, long Capacity)
{
    public double Percent => Capacity <= 0 ? 0 : 100.0 * Used / Capacity;
}

/// <summary>
/// Warns before a DHCP pool runs dry (the DHCP doctor only said so when someone ran it). Every
/// 5 minutes: ≥ 85 % raises a warning, ≥ 95 % a danger alert on the banner; it resolves below 80 %
/// (hysteresis — a pool hovering at the threshold doesn't flap). Runs in the DHCP server.
/// </summary>
public sealed class DhcpPoolAlertService(
    NpgsqlDataSource dataSource,
    IServiceScopeFactory scopes,
    ILogger<DhcpPoolAlertService> logger) : BackgroundService
{
    public static readonly TimeSpan Interval = TimeSpan.FromMinutes(5);
    internal const double WarnAt = 85, DangerAt = 95, ResolveBelow = 80;

    /// <summary>The alert a pool deserves now: severity, or null = resolve (below the band). Pure.</summary>
    internal static string? SeverityFor(PoolUsage usage, bool currentlyAlerting) => usage.Percent switch
    {
        >= DangerAt => "danger",
        >= WarnAt => "warning",
        >= ResolveBelow when currentlyAlerting => "warning",   // inside the hysteresis band: keep it up
        _ => null,
    };

    private readonly HashSet<Guid> _alerting = [];

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);
        do
        {
            try { await CheckOnceAsync(stoppingToken).ConfigureAwait(false); }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex) { logger.LogWarning(ex, "DHCP pool usage check failed"); }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
    }

    internal async Task CheckOnceAsync(CancellationToken ct)
    {
        await using var scope = scopes.CreateAsyncScope();
        var alerts = scope.ServiceProvider.GetRequiredService<ISystemAlertWriter>();
        foreach (var usage in await UsageAsync(ct).ConfigureAwait(false))
        {
            var key = $"dhcp-pool:{usage.PoolId}";
            var severity = SeverityFor(usage, _alerting.Contains(usage.PoolId));
            if (severity is null)
            {
                if (_alerting.Remove(usage.PoolId)) await alerts.ResolveAlertAsync(key, ct).ConfigureAwait(false);
                continue;
            }
            _alerting.Add(usage.PoolId);
            await alerts.RaiseAlertAsync(new SystemAlert
            {
                Source = "dhcp", Severity = severity, DedupeKey = key,
                Title = $"DHCP pool {usage.Pool} ({usage.Subnet}) is {usage.Percent:0}% full",
                Body = $"{usage.Used} of {usage.Capacity} addresses are leased. New devices won't get an address once it's full — widen the range or shorten the lease time.",
            }, ct).ConfigureAwait(false);
        }
    }

    internal async Task<IReadOnlyList<PoolUsage>> UsageAsync(CancellationToken ct)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = new NpgsqlCommand("""
            SELECT p.id, s.name, COALESCE(p.name, host(p.range_start) || '–' || host(p.range_end)),
                   (SELECT count(*) FROM dhcp_leases l
                     WHERE l.end_time > now() AND l.ip_address BETWEEN p.range_start AND p.range_end),
                   (p.range_end - p.range_start) + 1
                   - (SELECT count(*) FROM dhcp_exclusions e, generate_series(0, (COALESCE(e.ip_end, e.ip_start) - e.ip_start)) g
                       WHERE e.subnet_id = s.id AND (e.ip_start + g) BETWEEN p.range_start AND p.range_end)
            FROM dhcp_pools p JOIN dhcp_subnets s ON s.id = p.subnet_id
            WHERE p.enabled AND s.enabled
            """, conn);
        await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        var list = new List<PoolUsage>();
        while (await r.ReadAsync(ct).ConfigureAwait(false))
            list.Add(new PoolUsage(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetInt64(3), r.GetInt64(4)));
        return list;
    }
}
