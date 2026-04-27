using System.Net;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Network;

namespace NetFirewall.Services.Network;

public sealed class NetworkObjectResolver : INetworkObjectResolver
{
    private readonly INetworkObjectService _objects;
    private readonly ILogger<NetworkObjectResolver> _logger;

    public NetworkObjectResolver(INetworkObjectService objects, ILogger<NetworkObjectResolver> logger)
    {
        _objects = objects;
        _logger = logger;
    }

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
            ExpandObject(obj, catalogByName, result, visited);
        }

        // De-dupe while preserving first-seen order.
        return result.Distinct().ToList();
    }

    private void ExpandObject(NetworkObject obj, Dictionary<string, NetworkObject> catalog,
                              List<string> sink, HashSet<Guid> visited)
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
            case NetworkObjectTypes.Group:
                if (obj.Members is { } members)
                    foreach (var child in members) ExpandObject(child, catalog, sink, visited);
                break;
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
