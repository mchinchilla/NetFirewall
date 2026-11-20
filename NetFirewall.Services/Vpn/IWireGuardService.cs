using NetFirewall.Models.Vpn;

namespace NetFirewall.Services.Vpn;

/// <summary>
/// CRUD over <c>wg_servers</c> (one row per WireGuard interface) + <c>wg_peers</c>.
/// An interface is either the remote-access SERVER (<c>mode='server'</c>: listens, accepts
/// road-warrior clients and inbound sites) or an outbound CLIENT connection
/// (<c>mode='client'</c>: dials one provider or remote site). Callers always say WHICH
/// interface they mean — there is no "the" interface.
/// </summary>
public interface IWireGuardService
{
    /// <summary>Every interface, server kind first, then by creation.</summary>
    Task<IReadOnlyList<WgServer>> ListServersAsync(CancellationToken ct = default);

    Task<WgServer?> GetServerByIdAsync(Guid id, CancellationToken ct = default);

    Task<WgServer?> GetServerByNameAsync(string name, CancellationToken ct = default);

    /// <summary>Insert or update — keyed by Id; if Id is empty we create.</summary>
    Task<WgServer> SaveServerAsync(WgServer server, CancellationToken ct = default);

    Task<bool> DeleteServerAsync(Guid id, CancellationToken ct = default);

    Task<IReadOnlyList<WgPeer>> GetPeersAsync(Guid serverId, CancellationToken ct = default);
    Task<WgPeer?> GetPeerByIdAsync(Guid id, CancellationToken ct = default);
    Task<WgPeer> CreatePeerAsync(WgPeer peer, CancellationToken ct = default);
    Task<WgPeer> UpdatePeerAsync(WgPeer peer, CancellationToken ct = default);
    Task<bool> DeletePeerAsync(Guid id, CancellationToken ct = default);

    /// <summary>Re-home peers onto another interface, keeping their ids (their [vpn-auto] tags stay valid). Split/revert only.</summary>
    Task<int> MovePeersAsync(IReadOnlyCollection<Guid> peerIds, Guid toServerId, CancellationToken ct = default);
}
