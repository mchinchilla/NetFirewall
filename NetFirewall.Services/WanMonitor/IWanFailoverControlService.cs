using NetFirewall.Models;

namespace NetFirewall.Services.WanMonitor;

/// <summary>
/// Operator-facing WAN failover control: read the current state and manually
/// force which WAN is the active default route (a sticky override). Distinct
/// from the daemon's automatic <c>WanHealthMonitorService</c> — this is the
/// human-in-the-loop path the UI and the swap endpoint call.
/// </summary>
public interface IWanFailoverControlService
{
    /// <summary>
    /// Pin <paramref name="interfaceId"/> as the active WAN: set the sticky
    /// override and immediately swap the default route to it (don't wait for the
    /// next probe cycle). The monitor will keep it active until it goes down,
    /// then auto-clear the override. Returns success + a human message.
    /// </summary>
    Task<ServiceResponse<bool>> ForceActiveAsync(Guid interfaceId, string? setBy, CancellationToken ct = default);

    /// <summary>Clear the manual override and return to automatic priority-based selection.</summary>
    Task<ServiceResponse<bool>> ClearOverrideAsync(string? setBy, CancellationToken ct = default);
}
