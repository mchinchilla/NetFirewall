namespace NetFirewall.Web.Services;

/// <summary>
/// Read-only view over a directory of reference scripts (bash, nftables conf,
/// rt_tables, etc). Backs the "Bash scripts" admin page so operators can
/// inspect what the firewall is being modeled after — no execution path here
/// on purpose; ad-hoc script execution is its own can of worms and lives in
/// a future iteration with explicit allowlisting + step-up auth.
/// </summary>
public interface IBashScriptCatalog
{
    /// <summary>Files at the catalog root, sorted by name.</summary>
    Task<IReadOnlyList<BashScriptEntry>> ListAsync(CancellationToken ct = default);

    /// <summary>Full text content of one file. Returns null when not found or outside the root.</summary>
    Task<string?> ReadAsync(string name, CancellationToken ct = default);
}

public sealed record BashScriptEntry(
    string Name,
    string RelativePath,
    long SizeBytes,
    DateTime LastModified,
    string Kind);

public sealed class BashScriptCatalogOptions
{
    /// <summary>Directory the catalog reads from. Default points at the repo's /Bash folder for dev.</summary>
    public string Root { get; set; } = "Bash";

    /// <summary>Hard cap on the file size we'll read into memory (1 MB default).</summary>
    public long MaxFileSizeBytes { get; set; } = 1_048_576;
}
