using NetFirewall.Models.Network;

namespace NetFirewall.Services.Network;

/// <summary>
/// CRUD over <c>network_objects</c> + <c>network_object_members</c>.
/// Members are loaded into <see cref="NetworkObject.Members"/> only when
/// <c>includeMembers</c> is true — the table view doesn't need them.
/// </summary>
public interface INetworkObjectService
{
    Task<IReadOnlyList<NetworkObject>> GetAllAsync(bool includeMembers = false, CancellationToken ct = default);
    Task<NetworkObject?> GetByIdAsync(Guid id, bool includeMembers = false, CancellationToken ct = default);
    Task<NetworkObject?> GetByNameAsync(string name, bool includeMembers = false, CancellationToken ct = default);
    Task<NetworkObject> CreateAsync(NetworkObject obj, CancellationToken ct = default);
    Task<NetworkObject> UpdateAsync(NetworkObject obj, CancellationToken ct = default);
    Task<bool> DeleteAsync(Guid id, CancellationToken ct = default);

    /// <summary>Replace the full set of children for a group object. Throws if parent isn't a group.</summary>
    Task SetGroupMembersAsync(Guid parentId, IEnumerable<Guid> childIds, CancellationToken ct = default);

    /// <summary>
    /// Find every firewall rule that references this object by name. Useful
    /// before delete (so the operator sees what will silently break at next
    /// apply) and as a "where used" panel in the Edit drawer.
    /// </summary>
    Task<NetworkObjectUsage> FindUsagesAsync(string objectName, CancellationToken ct = default);
}

public sealed record NetworkObjectUsage(
    IReadOnlyList<UsageEntry> FilterRules,
    IReadOnlyList<UsageEntry> PortForwards,
    IReadOnlyList<UsageEntry> NatRules,
    IReadOnlyList<UsageEntry> MangleRules,
    IReadOnlyList<UsageEntry> ParentGroups)
{
    public int TotalCount =>
        FilterRules.Count + PortForwards.Count + NatRules.Count + MangleRules.Count + ParentGroups.Count;
}

public sealed record UsageEntry(Guid Id, string Description, string Field);
