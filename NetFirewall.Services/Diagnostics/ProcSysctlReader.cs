using System.Text.RegularExpressions;

namespace NetFirewall.Services.Diagnostics;

public sealed partial class ProcSysctlReader : ISysctlReader
{
    private const string Root = "/proc/sys";

    public async Task<string?> ReadAsync(string relativePath, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsLinux()) return null;
        // Relative, no traversal, only the characters sysctl paths actually use.
        if (!PathRx().IsMatch(relativePath) || relativePath.Contains("..", StringComparison.Ordinal)) return null;

        var full = Path.Combine(Root, relativePath);
        try { return (await File.ReadAllTextAsync(full, ct)).Trim(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    [GeneratedRegex(@"^[a-z0-9_][A-Za-z0-9_.\-/]{0,120}$")]
    private static partial Regex PathRx();
}
