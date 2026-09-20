using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics;

/// <summary>
/// Kernel-journal explorer for the nftables <c>log prefix</c> lines
/// (<c>INPUT_DROP</c>, <c>FORWARD_DROP</c>, <c>SPOOFED_SRC</c>, <c>BLOCKED_SCAN</c>…),
/// martian-source reports and wg-quick noise. Reads <c>journalctl -k</c> — the
/// daemon unit has <c>ProtectKernelLogs=yes</c>, so <c>dmesg</c> is off the table.
/// </summary>
public interface IDropLogService
{
    /// <param name="iface">Keep only lines whose IN= or OUT= is this interface (nflog lines only).</param>
    /// <param name="filter">drops | martians | wg | all</param>
    Task<DropLogResult> QueryAsync(string? iface, int sinceMinutes, int lines, string filter, CancellationToken ct = default);
}
