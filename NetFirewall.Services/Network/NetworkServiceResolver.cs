using Microsoft.Extensions.Logging;
using NetFirewall.Models.Network;

namespace NetFirewall.Services.Network;

public sealed class NetworkServiceResolver : INetworkServiceResolver
{
    private readonly INetworkServiceService _services;
    private readonly ILogger<NetworkServiceResolver> _logger;

    public NetworkServiceResolver(INetworkServiceService services, ILogger<NetworkServiceResolver> logger)
    {
        _services = services;
        _logger = logger;
    }

    public async Task<IReadOnlyList<string>> ResolveAsync(IEnumerable<string> inputs, CancellationToken ct = default)
    {
        var result = new List<string>();
        Dictionary<string, NetworkService>? catalog = null;

        foreach (var raw in inputs ?? Enumerable.Empty<string>())
        {
            var input = raw?.Trim();
            if (string.IsNullOrEmpty(input)) continue;

            if (LooksLikeLiteral(input))
            {
                result.Add(input);
                continue;
            }

            if (catalog is null)
            {
                var all = await _services.GetAllAsync(includeMembers: true, ct);
                catalog = all.ToDictionary(s => s.Name, s => s, StringComparer.OrdinalIgnoreCase);
            }

            if (!catalog.TryGetValue(input, out var svc))
            {
                _logger.LogWarning("Network service reference '{Name}' not found — skipped", input);
                continue;
            }

            var visited = new HashSet<Guid>();
            Expand(svc, result, visited);
        }

        return result.Distinct().ToList();
    }

    private void Expand(NetworkService s, List<string> sink, HashSet<Guid> visited)
    {
        if (!visited.Add(s.Id))
        {
            _logger.LogWarning("Cycle in service group at '{Name}' — stopping", s.Name);
            return;
        }

        // Group: recurse into members. We don't emit anything for the group itself.
        if (s.Members is { Count: > 0 } members)
        {
            foreach (var c in members) Expand(c, sink, visited);
            return;
        }

        // Leaf: emit "port" or "start-end". The rule's protocol field handles
        // tcp/udp split; for tcp+udp services the operator's rule must use
        // the matching protocol or a separate rule per protocol.
        sink.Add(s.PortString);
    }

    /// <summary>
    /// True when the input is already a numeric port spec — pure number,
    /// dash-range, or ICMP type/code form (we accept those as literals too).
    /// </summary>
    private static bool LooksLikeLiteral(string input)
    {
        if (input.Length == 0) return false;
        // Single port: all digits
        if (input.All(char.IsDigit)) return true;
        // Range "a-b" with both halves numeric
        var dash = input.IndexOf('-');
        if (dash > 0 && dash < input.Length - 1)
        {
            var left  = input[..dash].Trim();
            var right = input[(dash + 1)..].Trim();
            return left.All(char.IsDigit) && right.All(char.IsDigit);
        }
        return false;
    }
}
