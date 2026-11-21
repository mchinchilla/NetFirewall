using NetFirewall.Models.Dhcp;

namespace NetFirewall.Services.Dhcp;

/// <summary>
/// In-memory <see cref="DhcpRelayPolicy"/> built from <c>dhcp_relay_agents</c> for the DHCP
/// server (singleton). Dropped by the <c>relay.changed</c> NOTIFY (migration 00054).
/// </summary>
public interface IDhcpRelayTrustCache
{
    ValueTask<DhcpRelayPolicy> GetPolicyAsync(CancellationToken ct = default);

    void Invalidate();
}
