using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging;

namespace NetFirewall.Services.Dhcp;

/// <summary>Is an address already in use on the wire, before we offer it?</summary>
public interface IAddressProbe
{
    Task<bool> IsInUseAsync(IPAddress address, CancellationToken ct = default);
}

/// <summary>
/// ICMP echo before offering a NEW pool address (ISC's ping-check): a device with a hand-set
/// static IP inside the pool would otherwise be handed to a second client — an address conflict
/// only that client's DECLINE (if it ARP-checks at all) would reveal. 250 ms per probe; a "free"
/// answer is cached 10 minutes so a client's repeated DISCOVERs don't ping again (the DHCP
/// pipeline is single-consumer — every probe delays it). Failures to ping count as free.
/// </summary>
public sealed class IcmpAddressProbe(ILogger<IcmpAddressProbe> logger) : IAddressProbe
{
    internal static readonly TimeSpan Timeout = TimeSpan.FromMilliseconds(250);
    internal static readonly TimeSpan FreeFor = TimeSpan.FromMinutes(10);
    private readonly ConcurrentDictionary<IPAddress, DateTime> _knownFree = new();

    public async Task<bool> IsInUseAsync(IPAddress address, CancellationToken ct = default)
    {
        if (_knownFree.TryGetValue(address, out var until) && until > DateTime.UtcNow) return false;
        try
        {
            using var ping = new Ping();
            var reply = await ping.SendPingAsync(address, Timeout, buffer: null, options: null, ct).ConfigureAwait(false);
            if (reply.Status == IPStatus.Success) return true;
        }
        catch (Exception ex) when (ex is PingException or InvalidOperationException or NotSupportedException)
        {
            logger.LogDebug(ex, "Ping check of {Ip} failed — treating it as free", address);
        }
        _knownFree[address] = DateTime.UtcNow + FreeFor;
        if (_knownFree.Count > 4096)   // bounded: drop expired entries
            foreach (var (ip, exp) in _knownFree)
                if (exp <= DateTime.UtcNow) _knownFree.TryRemove(new KeyValuePair<IPAddress, DateTime>(ip, exp));
        return false;
    }
}
