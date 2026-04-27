namespace NetFirewall.Services.Network;

/// <summary>
/// Resolves a mix of literal port specifications (<c>22</c>, <c>10000-20000</c>)
/// and network-service references (<c>SSH</c>, <c>RTP</c>) into a flat list
/// of nft-ready port strings ready to drop into a <c>dport { ... }</c> set.
/// Sister of <see cref="INetworkObjectResolver"/> — same shape, different
/// catalog (network_services instead of network_objects).
/// </summary>
public interface INetworkServiceResolver
{
    Task<IReadOnlyList<string>> ResolveAsync(IEnumerable<string> inputs, CancellationToken ct = default);
}
