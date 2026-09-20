namespace NetFirewall.Services.Diagnostics;

/// <summary>
/// Reads kernel tunables from <c>/proc/sys</c> by path (<c>net/ipv4/conf/wg0/rp_filter</c>),
/// not by dotted key — interface names may contain dots, which the dotted form
/// cannot represent unambiguously. Null off-Linux or when the file is absent.
/// </summary>
public interface ISysctlReader
{
    Task<string?> ReadAsync(string relativePath, CancellationToken ct = default);
}
