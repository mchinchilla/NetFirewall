using NetFirewall.Models.Vpn;

namespace NetFirewall.Services.Diagnostics;

/// <summary>Live WireGuard state for diagnostics (<c>wg show &lt;iface&gt; dump</c>, secrets stripped at parse time).</summary>
public interface IWgLiveReader
{
    /// <summary>Null when the interface does not exist or <c>wg</c> failed.</summary>
    Task<WgDump?> DumpAsync(string iface, CancellationToken ct = default);
}
