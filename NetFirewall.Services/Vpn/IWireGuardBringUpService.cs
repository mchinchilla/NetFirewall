using NetFirewall.Models.Vpn;

namespace NetFirewall.Services.Vpn;

/// <summary>
/// Bring-up orchestration for a WireGuard interface: write the config, bring
/// the link up (or hot-reload it), then put the tunnel's policy routes back.
/// One choke point behind <c>POST /v1/wireguard/apply</c>, so the Web "Start"
/// button, the combined apply and the TUI all get the same behaviour.
/// </summary>
public interface IWireGuardBringUpService
{
    Task<WireGuardBringUpResult> ApplyAsync(WgServer server, IReadOnlyList<WgPeer> peers, CancellationToken ct = default);
}
