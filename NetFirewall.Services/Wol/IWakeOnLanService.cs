using NetFirewall.Models;
using NetFirewall.Models.Wol;

namespace NetFirewall.Services.Wol;

/// <summary>
/// Daemon-side Wake-on-LAN: validates the request (never trusting the Web's
/// check), picks the LAN link, and puts the magic packet on it. Every failure
/// comes back as a <see cref="ServiceResponse{T}"/> with a sentence the operator
/// can act on; nothing throws.
/// </summary>
public interface IWakeOnLanService
{
    Task<ServiceResponse<WolWakeResult>> WakeAsync(WolWakeRequest request, CancellationToken ct = default);
}
