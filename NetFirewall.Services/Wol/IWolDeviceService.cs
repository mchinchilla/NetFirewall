using NetFirewall.Models;
using NetFirewall.Models.Wol;

namespace NetFirewall.Services.Wol;

/// <summary>
/// CRUD over <c>wol_devices</c>. Reads join DHCP by MAC so every row carries the
/// device's reserved (else last-leased) IP and hostname. Writes validate again
/// here — the form's checks are a convenience, not the guard.
/// </summary>
public interface IWolDeviceService
{
    Task<IReadOnlyList<WolDevice>> GetAllAsync(CancellationToken ct = default);
    Task<WolDevice?> GetByIdAsync(Guid id, CancellationToken ct = default);

    /// <summary>Fails (no throw) on invalid fields or a name/MAC another device already uses.</summary>
    Task<ServiceResponse<WolDevice>> SaveAsync(WolDevice device, CancellationToken ct = default);

    Task<bool> DeleteAsync(Guid id, CancellationToken ct = default);

    /// <summary>Stamps <c>last_woken_at/by</c> after the daemon confirmed the send.</summary>
    Task MarkWokenAsync(Guid id, string? by, CancellationToken ct = default);
}
