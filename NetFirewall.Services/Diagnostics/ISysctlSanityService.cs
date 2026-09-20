using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics;

/// <summary>
/// Runtime kernel-tunable checks a firewall depends on: forwarding on, reverse-path
/// filter loose (strict silently drops policy-routed replies), martian logging,
/// conntrack table headroom. Used by the Sysctl page and embedded by every doctor.
/// </summary>
public interface ISysctlSanityService
{
    /// <param name="iface">Optional interface whose per-device rp_filter is combined with <c>all</c> (effective = max).</param>
    Task<IReadOnlyList<DiagCheck>> EvaluateAsync(string? iface, CancellationToken ct = default);
}
