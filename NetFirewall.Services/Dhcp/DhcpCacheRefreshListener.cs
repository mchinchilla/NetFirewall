using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace NetFirewall.Services.Dhcp;

/// <summary>
/// Background service that holds a long-lived Postgres connection in
/// LISTEN mode for <see cref="IDhcpCacheNotifier.SubnetChannel"/>. Each
/// notification calls <see cref="IDhcpSubnetService.InvalidateCache"/> so
/// the next subnet lookup refetches from DB.
///
/// Lives in <c>NetFirewall.DhcpServer</c> only — the Web doesn't need it.
/// </summary>
public sealed class DhcpCacheRefreshListener : BackgroundService
{
    private readonly NpgsqlDataSource _ds;
    private readonly IDhcpSubnetService _subnets;
    private readonly ILogger<DhcpCacheRefreshListener> _logger;

    public DhcpCacheRefreshListener(
        NpgsqlDataSource ds,
        IDhcpSubnetService subnets,
        ILogger<DhcpCacheRefreshListener> logger)
    {
        _ds = ds;
        _subnets = subnets;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Loop with backoff so a transient DB outage doesn't kill the service.
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ListenLoopAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "LISTEN loop crashed; reconnecting in 5s");
                try { await Task.Delay(TimeSpan.FromSeconds(5), stoppingToken); }
                catch (OperationCanceledException) { break; }
            }
        }

        _logger.LogInformation("DHCP cache refresh listener stopped");
    }

    private async Task ListenLoopAsync(CancellationToken ct)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        conn.Notification += OnNotification;

        await using (var cmd = new NpgsqlCommand($"LISTEN {IDhcpCacheNotifier.SubnetChannel}", conn))
        {
            await cmd.ExecuteNonQueryAsync(ct);
        }

        _logger.LogInformation("Listening for {Channel} notifications", IDhcpCacheNotifier.SubnetChannel);

        // WaitAsync blocks until a NOTIFY arrives; the event handler fires
        // synchronously on the connection's read pump.
        while (!ct.IsCancellationRequested)
        {
            await conn.WaitAsync(ct);
        }
    }

    private void OnNotification(object _, NpgsqlNotificationEventArgs e)
    {
        _logger.LogDebug("Got NOTIFY {Channel}: {Payload}", e.Channel, e.Payload);
        try
        {
            _subnets.InvalidateCache();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Subnet cache invalidation handler threw");
        }
    }
}
