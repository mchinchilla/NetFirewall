using System.Collections.Concurrent;
using System.Net;
using System.Threading.Channels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Monitoring;

namespace NetFirewall.Services.Dhcp;

/// <summary>A DHCP server reply seen on a LAN that didn't come from this firewall.</summary>
public sealed record ForeignDhcpReply(string Interface, IPAddress ServerIp, string ServerMac);

/// <summary>Sightings from the receive path. Never blocks the packet loop.</summary>
public interface IRogueDhcpMonitor
{
    void Observe(ForeignDhcpReply reply);
}

/// <summary>
/// Rogue DHCP detection: another server answering on our LAN (an ISP router left in router mode,
/// a misconfigured AP, a test VM) hands out wrong gateways and splits the network. The raw socket
/// already sees every frame; any BOOTREPLY from an address that isn't ours is a sighting. Raises a
/// danger alert per (interface, server) at most every 10 minutes and resolves it after an hour
/// without sightings. (A DHCP relay on the segment answers too — the alert says so.)
/// </summary>
public sealed class RogueDhcpMonitor(IServiceScopeFactory scopes, ILogger<RogueDhcpMonitor> logger)
    : BackgroundService, IRogueDhcpMonitor
{
    internal static readonly TimeSpan Reraise = TimeSpan.FromMinutes(10);
    internal static readonly TimeSpan ResolveAfter = TimeSpan.FromHours(1);

    private readonly Channel<ForeignDhcpReply> _sightings = Channel.CreateBounded<ForeignDhcpReply>(
        new BoundedChannelOptions(256) { FullMode = BoundedChannelFullMode.DropNewest, SingleReader = true });
    private readonly ConcurrentDictionary<string, (DateTime LastSeen, DateTime LastRaised)> _servers = new();

    public void Observe(ForeignDhcpReply reply) => _sightings.Writer.TryWrite(reply);

    internal static string Key(ForeignDhcpReply r) => $"dhcp-rogue:{r.Interface}:{r.ServerIp}";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var sweep = new PeriodicTimer(TimeSpan.FromMinutes(5));
        var reading = _sightings.Reader.WaitToReadAsync(stoppingToken).AsTask();
        var ticking = sweep.WaitForNextTickAsync(stoppingToken).AsTask();
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var done = await Task.WhenAny(reading, ticking).ConfigureAwait(false);
                if (done == reading)
                {
                    if (!await reading.ConfigureAwait(false)) break;
                    while (_sightings.Reader.TryRead(out var r)) await HandleAsync(r, DateTime.UtcNow, stoppingToken).ConfigureAwait(false);
                    reading = _sightings.Reader.WaitToReadAsync(stoppingToken).AsTask();
                }
                else
                {
                    if (!await ticking.ConfigureAwait(false)) break;
                    await SweepAsync(DateTime.UtcNow, stoppingToken).ConfigureAwait(false);
                    ticking = sweep.WaitForNextTickAsync(stoppingToken).AsTask();
                }
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Rogue DHCP monitor step failed");
                reading = _sightings.Reader.WaitToReadAsync(stoppingToken).AsTask();
                ticking = sweep.WaitForNextTickAsync(stoppingToken).AsTask();
            }
        }
    }

    internal async Task HandleAsync(ForeignDhcpReply r, DateTime now, CancellationToken ct)
    {
        var key = Key(r);
        var known = _servers.TryGetValue(key, out var s);
        _servers[key] = (now, known ? s.LastRaised : DateTime.MinValue);
        if (known && now - s.LastRaised < Reraise) return;

        logger.LogWarning("Another DHCP server answered on {Iface}: {Ip} ({Mac})", r.Interface, r.ServerIp, r.ServerMac);
        await using var scope = scopes.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<ISystemAlertWriter>().RaiseAlertAsync(new SystemAlert
        {
            Source = "dhcp", Severity = "danger", DedupeKey = key,
            Title = $"Another DHCP server is answering on {r.Interface}: {r.ServerIp}",
            Body = $"Device {r.ServerMac} at {r.ServerIp} is handing out addresses on this network. Clients that take its offer get its gateway and DNS instead of this firewall's. Usually an ISP router or access point with DHCP left on — turn it off there. (A DHCP relay on this segment also shows up here.)",
        }, ct).ConfigureAwait(false);
        _servers[key] = (now, now);
    }

    internal async Task SweepAsync(DateTime now, CancellationToken ct)
    {
        foreach (var (key, s) in _servers)
        {
            if (now - s.LastSeen < ResolveAfter) continue;
            if (!_servers.TryRemove(new KeyValuePair<string, (DateTime, DateTime)>(key, s))) continue;
            await using var scope = scopes.CreateAsyncScope();
            await scope.ServiceProvider.GetRequiredService<ISystemAlertWriter>().ResolveAlertAsync(key, ct).ConfigureAwait(false);
        }
    }
}
