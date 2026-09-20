using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics.Vpn;

/// <summary>
/// The VPN doctor: a checklist over config, interface, handshake, path, policy
/// routing, firewall, kernel and journal that pinpoints where a tunnel's packets
/// die — plus the two hands-on tools that finished yesterday's investigation:
/// a data-plane probe and a compare-against-issued-config.
/// </summary>
public interface IVpnDoctorService
{
    /// <summary>Run every registered check concurrently under the doctor budget. Never throws for a check failure.</summary>
    Task<DiagReport> RunAsync(VpnDoctorRequest request, CancellationToken ct = default);

    /// <summary>
    /// Ping through the tunnel by fwmark and/or bound to the interface, with
    /// <c>wg show</c> transfer counters before/after, and classify the outcome:
    /// ok · remote-drops (tx grows, rx flat — the far end discards our source) ·
    /// local-routing (nothing entered the tunnel) · replies-dropped (rx grows, no
    /// replies — rp_filter/INPUT) · no-interface · inconclusive.
    /// </summary>
    Task<VpnProbeResult> ProbeAsync(VpnProbeRequest request, CancellationToken ct = default);

    /// <summary>Diff a pasted (already redacted) wg-quick client config against what this firewall runs.</summary>
    Task<VpnCompareResult> CompareIssuedConfigAsync(string redactedConfigText, CancellationToken ct = default);
}
