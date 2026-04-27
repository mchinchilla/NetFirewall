using NetFirewall.Models.Network;

namespace NetFirewall.Services.Network;

/// <summary>
/// CRUD over <c>network_services</c> + <c>network_service_groups</c>.
/// Mirror of <see cref="INetworkObjectService"/> but for L4 (port/protocol).
/// Used by filter / mangle / port-forward generators to expand named refs
/// (e.g. <c>SSH</c>) into concrete port numbers / ranges at apply time.
/// </summary>
public interface INetworkServiceService
{
    Task<IReadOnlyList<NetworkService>> GetAllAsync(bool includeMembers = false, CancellationToken ct = default);
    Task<NetworkService?> GetByIdAsync(Guid id, bool includeMembers = false, CancellationToken ct = default);
    Task<NetworkService?> GetByNameAsync(string name, bool includeMembers = false, CancellationToken ct = default);
    Task<NetworkService> CreateAsync(NetworkService s, CancellationToken ct = default);
    Task<NetworkService> UpdateAsync(NetworkService s, CancellationToken ct = default);
    Task<bool> DeleteAsync(Guid id, CancellationToken ct = default);

    Task SetGroupMembersAsync(Guid parentId, IEnumerable<Guid> childIds, CancellationToken ct = default);
}
