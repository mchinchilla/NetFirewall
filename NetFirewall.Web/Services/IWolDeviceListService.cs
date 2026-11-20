using NetFirewall.Web.Models.Network;

namespace NetFirewall.Web.Services;

/// <summary>
/// Saved Wake-on-LAN devices joined with their ARP presence from the daemon. Backs the
/// Wake-on-LAN grid; the daemon being down blanks the status, never the list.
/// </summary>
public interface IWolDeviceListService
{
    Task<WolDevicesTableViewModel> GetAsync(CancellationToken ct = default);
}
