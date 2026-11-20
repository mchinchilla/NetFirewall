using NetFirewall.Models.Vpn;

namespace NetFirewall.Services.Monitoring;

/// <summary>
/// Raise / resolve rows in system_alerts (the notification banner), by dedupe key. Upsert
/// semantics: re-raising refreshes title/severity and keeps the original raised_at. Generic —
/// VPN, DHCP and others share it. Implemented by VpnHealthService (where the table was born).
/// </summary>
public interface ISystemAlertWriter
{
    Task RaiseAlertAsync(SystemAlert alert, CancellationToken ct = default);
    Task ResolveAlertAsync(string dedupeKey, CancellationToken ct = default);
}
