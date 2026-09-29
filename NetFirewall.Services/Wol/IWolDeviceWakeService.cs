using NetFirewall.Models;
using NetFirewall.Models.Wol;

namespace NetFirewall.Services.Wol;

/// <summary>
/// Web-side wake of SAVED devices: looks the device up, asks the daemon to send
/// (it re-validates and picks nothing — a saved device names its interface and
/// port), and stamps <c>last_woken_*</c> for each packet that actually left.
/// </summary>
public interface IWolDeviceWakeService
{
    Task<ServiceResponse<WolWakeResult>> WakeAsync(Guid deviceId, string? by, CancellationToken ct = default);

    /// <summary>
    /// The given saved devices — or every one when <paramref name="deviceIds"/> is
    /// null/empty — a few at a time. Ids that no longer exist are skipped. Success
    /// only when every wake was sent; otherwise <see cref="ServiceResponse{T}.Errors"/>
    /// holds one entry per device that failed (keyed by name) and
    /// <see cref="ServiceResponse{T}.Data"/> still carries the per-device outcome.
    /// </summary>
    Task<ServiceResponse<WolBatchResult>> WakeManyAsync(IReadOnlyCollection<Guid>? deviceIds, string? by, CancellationToken ct = default);
}
