using NetFirewall.Models;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Daemon;
using NetFirewall.Services.Wol;
using NetFirewall.Web.Models.Network;

namespace NetFirewall.Web.Services;

/// <summary>
/// One DB read (<see cref="IWolDeviceService"/>) plus one daemon call (the neighbour table),
/// skipped when there are no devices. Same join as <c>WakeOnLanController</c>'s table.
/// </summary>
public sealed class WolDeviceListService(IWolDeviceService devices, IDaemonClient daemon) : IWolDeviceListService
{
    public async Task<WolDevicesTableViewModel> GetAsync(CancellationToken ct = default)
    {
        var rows = await devices.GetAllAsync(ct);
        var neighbors = rows.Count == 0
            ? ServiceResponse<IReadOnlyList<NeighborEntry>>.Ok([])
            : await daemon.GetNeighborsAsync(null, ct);
        var arp = neighbors.Data ?? [];

        return new WolDevicesTableViewModel
        {
            Rows = rows.Select(d => new WolDeviceRow(d, WolPresence.For(d.MacAddress, arp))).ToList(),
            PresenceError = neighbors.Success ? null : neighbors.Message,
        };
    }
}
