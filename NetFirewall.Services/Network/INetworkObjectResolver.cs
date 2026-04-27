namespace NetFirewall.Services.Network;

/// <summary>
/// Resolves rule address fields (mix of literal CIDRs and object name
/// references) into a flat list of CIDRs ready for nft. The resolver is
/// the only thing that needs to know about object types, group nesting,
/// or future FQDN lookups — generators stay stupid.
///
/// Naming convention: anything that contains a <c>/</c>, a <c>-</c>, or a
/// dot+digit pattern is treated as a literal IP/CIDR/range and passed
/// through unchanged. Everything else is looked up by name in the catalog.
/// </summary>
public interface INetworkObjectResolver
{
    /// <summary>Expand inputs (literals + named objects) into flat CIDRs.</summary>
    Task<IReadOnlyList<string>> ResolveAsync(IEnumerable<string> inputs, CancellationToken ct = default);
}
