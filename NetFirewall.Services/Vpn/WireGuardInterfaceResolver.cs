using NetFirewall.Models.Vpn;

namespace NetFirewall.Services.Vpn;

/// <summary>
/// Which WireGuard interface a request means. Pages may default (the remote-access server sorts
/// first); anything that CHANGES state must name its interface — a view that forgets the
/// parameter must fail, never silently rotate or stop wg0. Names only ever select stored rows.
/// </summary>
public interface IWireGuardInterfaceResolver
{
    /// <summary>For GET pages: the named interface, else the first one (server kind first).</summary>
    Task<WgServer?> ForPageAsync(string? iface, CancellationToken ct = default);

    /// <summary>For mutations: the named interface or null. Never a default.</summary>
    Task<WgServer?> RequireAsync(string? iface, CancellationToken ct = default);

    /// <summary>Every interface with its peers (one round per interface).</summary>
    Task<IReadOnlyList<(WgServer Server, IReadOnlyList<WgPeer> Peers)>> ListWithPeersAsync(CancellationToken ct = default);
}

public sealed class WireGuardInterfaceResolver(IWireGuardService wg) : IWireGuardInterfaceResolver
{
    public async Task<WgServer?> ForPageAsync(string? iface, CancellationToken ct = default) =>
        string.IsNullOrWhiteSpace(iface)
            ? (await wg.ListServersAsync(ct)).FirstOrDefault()
            : await RequireAsync(iface, ct);

    public async Task<WgServer?> RequireAsync(string? iface, CancellationToken ct = default) =>
        WgInterfaceName.IsValid(iface?.Trim()) ? await wg.GetServerByNameAsync(iface!.Trim(), ct) : null;

    public async Task<IReadOnlyList<(WgServer Server, IReadOnlyList<WgPeer> Peers)>> ListWithPeersAsync(CancellationToken ct = default)
    {
        var list = new List<(WgServer, IReadOnlyList<WgPeer>)>();
        foreach (var s in await wg.ListServersAsync(ct))
            list.Add((s, await wg.GetPeersAsync(s.Id, ct)));
        return list;
    }
}
