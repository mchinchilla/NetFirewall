using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Network;
using NetFirewall.Services.Settings;

namespace NetFirewall.Services.Network;

public sealed class NetworkObjectResolver : INetworkObjectResolver
{
    private readonly INetworkObjectService _objects;
    private readonly IAppSettingsService _settings;
    private readonly ILogger<NetworkObjectResolver> _logger;

    // Process-wide DNS cache. Hostnames with the same fqdn share the entry
    // across requests. TTL re-read from settings on every miss so changes
    // in the Settings page take effect on the next eviction.
    private static readonly ConcurrentDictionary<string, FqdnCacheEntry> _fqdnCache =
        new(StringComparer.OrdinalIgnoreCase);

    public NetworkObjectResolver(
        INetworkObjectService objects,
        IAppSettingsService settings,
        ILogger<NetworkObjectResolver> logger)
    {
        _objects = objects;
        _settings = settings;
        _logger = logger;
    }

    private sealed record FqdnCacheEntry(IReadOnlyList<string> Cidrs, DateTimeOffset ExpiresAt);

    public async Task<IReadOnlyList<string>> ResolveAsync(IEnumerable<string> inputs, CancellationToken ct = default)
    {
        var result = new List<string>();
        // Cache the full catalog by name — most rules reference a small handful
        // of objects, so one fetch beats N lookups.
        Dictionary<string, NetworkObject>? catalogByName = null;

        foreach (var raw in inputs ?? Enumerable.Empty<string>())
        {
            var input = raw?.Trim();
            if (string.IsNullOrEmpty(input)) continue;

            if (LooksLikeLiteral(input))
            {
                result.Add(NormalizeLiteral(input));
                continue;
            }

            // It's a name reference — load catalog lazily.
            if (catalogByName is null)
            {
                var all = await _objects.GetAllAsync(includeMembers: true, ct);
                catalogByName = all.ToDictionary(o => o.Name, o => o, StringComparer.OrdinalIgnoreCase);
            }

            if (!catalogByName.TryGetValue(input, out var obj))
            {
                _logger.LogWarning("Network object reference '{Name}' not found — skipped", input);
                continue;
            }

            var visited = new HashSet<Guid>();
            await ExpandObjectAsync(obj, catalogByName, result, visited, ct);
        }

        // De-dupe while preserving first-seen order.
        return result.Distinct().ToList();
    }

    private async Task ExpandObjectAsync(
        NetworkObject obj,
        Dictionary<string, NetworkObject> catalog,
        List<string> sink,
        HashSet<Guid> visited,
        CancellationToken ct)
    {
        if (!visited.Add(obj.Id))
        {
            _logger.LogWarning("Cycle detected in network-object group at '{Name}' — stopping recursion", obj.Name);
            return;
        }

        switch (obj.Type)
        {
            case NetworkObjectTypes.Host:
                sink.Add(NormalizeLiteral(obj.Value));
                break;
            case NetworkObjectTypes.Network:
                sink.Add(obj.Value.Trim());
                break;
            case NetworkObjectTypes.Range:
                // nft accepts "1.2.3.4-1.2.3.50" as a range literal directly.
                sink.Add(obj.Value.Trim());
                break;
            case NetworkObjectTypes.Fqdn:
                foreach (var cidr in await ResolveFqdnAsync(obj.Value, ct))
                    sink.Add(cidr);
                break;
            case NetworkObjectTypes.Group:
                if (obj.Members is { } members)
                    foreach (var child in members)
                        await ExpandObjectAsync(child, catalog, sink, visited, ct);
                break;
        }
    }

    /// <summary>
    /// DNS-resolve <paramref name="fqdn"/> with a process-wide TTL cache. On
    /// transient failure we serve a stale entry if one exists (better to
    /// keep firewall config working with last-known IPs than to silently
    /// drop the rule).
    /// </summary>
    private async Task<IReadOnlyList<string>> ResolveFqdnAsync(string fqdn, CancellationToken ct)
    {
        var host = fqdn.Trim();
        if (string.IsNullOrEmpty(host)) return Array.Empty<string>();

        if (_fqdnCache.TryGetValue(host, out var hit) && hit.ExpiresAt > DateTimeOffset.UtcNow)
        {
            return hit.Cidrs;
        }

        var ttl = TimeSpan.FromSeconds(Math.Max(30, await _settings.GetIntAsync("network_objects.fqdn_ttl_seconds", ct)));

        try
        {
            var addrs = await Dns.GetHostAddressesAsync(host, ct);
            var cidrs = addrs
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => $"{a}/32")
                .Distinct()
                .ToList();

            if (cidrs.Count == 0)
            {
                _logger.LogWarning("FQDN '{Host}' resolved to zero IPv4 addresses", host);
                return Array.Empty<string>();
            }

            _fqdnCache[host] = new FqdnCacheEntry(cidrs, DateTimeOffset.UtcNow + ttl);
            _logger.LogDebug("FQDN '{Host}' resolved to {Count} addr(s), cached for {Ttl}", host, cidrs.Count, ttl);
            return cidrs;
        }
        catch (Exception ex)
        {
            // Serve stale on failure — better than dropping the rule entirely.
            if (hit is not null)
            {
                _logger.LogWarning(ex, "DNS lookup for '{Host}' failed; serving stale cache (expired {ExpiredAt})", host, hit.ExpiresAt);
                return hit.Cidrs;
            }
            _logger.LogError(ex, "DNS lookup for '{Host}' failed and no cache entry — rule will be skipped", host);
            return Array.Empty<string>();
        }
    }

    /// <summary>Add /32 if value is a bare IPv4 with no suffix.</summary>
    private static string NormalizeLiteral(string raw)
    {
        var v = raw.Trim();
        if (v.Contains('/') || v.Contains('-')) return v;
        return IPAddress.TryParse(v, out _) ? $"{v}/32" : v;
    }

    private static bool LooksLikeLiteral(string input)
    {
        // CIDR (a.b.c.d/n), range (a.b.c.d-a.b.c.e), or bare IPv4.
        if (input.Contains('/') || input.Contains('-')) return true;
        return IPAddress.TryParse(input, out _);
    }
}
