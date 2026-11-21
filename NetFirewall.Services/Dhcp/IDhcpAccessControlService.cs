using NetFirewall.Models;
using NetFirewall.Models.Dhcp;

namespace NetFirewall.Services.Dhcp;

/// <summary>
/// Web-side CRUD for DHCP → Access control: the MAC block list (dhcp_mac_blocklist) and the
/// trusted relay agents (dhcp_relay_agents). Every write validates here (the controller's
/// ModelState is the first line) and the DB triggers tell the DHCP server.
/// </summary>
public interface IDhcpAccessControlService
{
    Task<IReadOnlyList<DhcpBlockedMac>> GetBlockedMacsAsync(CancellationToken ct = default);
    Task<DhcpBlockedMac?> GetBlockedMacAsync(Guid id, CancellationToken ct = default);

    /// <summary>Create (Id empty) or update. Blocking also purges the device's leases.</summary>
    Task<ServiceResponse<DhcpBlockedMac>> SaveBlockedMacAsync(DhcpBlockedMac entry, CancellationToken ct = default);
    Task<ServiceResponse<bool>> DeleteBlockedMacAsync(Guid id, CancellationToken ct = default);

    Task<IReadOnlyList<DhcpRelayAgent>> GetRelayAgentsAsync(CancellationToken ct = default);
    Task<DhcpRelayAgent?> GetRelayAgentAsync(Guid id, CancellationToken ct = default);
    Task<ServiceResponse<DhcpRelayAgent>> SaveRelayAgentAsync(DhcpRelayAgent relay, CancellationToken ct = default);
    Task<ServiceResponse<bool>> DeleteRelayAgentAsync(Guid id, CancellationToken ct = default);
}
