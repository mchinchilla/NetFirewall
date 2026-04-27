using NetFirewall.Models.Vpn;

namespace NetFirewall.Services.Vpn;

/// <summary>
/// CRUD over <c>wg_servers</c> + <c>wg_peers</c>. Single-server design — there
/// is at most one row in <c>wg_servers</c> by convention. Multi-server is a
/// future iteration; the schema already keys peers by server_id so adding it
/// is additive.
/// </summary>
public interface IWireGuardService
{
    /// <summary>Returns the configured server, or null if none exists yet.</summary>
    Task<WgServer?> GetServerAsync(CancellationToken ct = default);

    /// <summary>Insert or update — keyed by Id; if Id is empty we create.</summary>
    Task<WgServer> SaveServerAsync(WgServer server, CancellationToken ct = default);

    Task<bool> DeleteServerAsync(Guid id, CancellationToken ct = default);

    Task<IReadOnlyList<WgPeer>> GetPeersAsync(Guid serverId, CancellationToken ct = default);
    Task<WgPeer?> GetPeerByIdAsync(Guid id, CancellationToken ct = default);
    Task<WgPeer> CreatePeerAsync(WgPeer peer, CancellationToken ct = default);
    Task<WgPeer> UpdatePeerAsync(WgPeer peer, CancellationToken ct = default);
    Task<bool> DeletePeerAsync(Guid id, CancellationToken ct = default);
}
