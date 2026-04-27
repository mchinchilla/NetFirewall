using Microsoft.Extensions.Options;

namespace NetFirewall.Web.Services;

public sealed class BashScriptCatalog : IBashScriptCatalog
{
    private readonly BashScriptCatalogOptions _opts;
    private readonly ILogger<BashScriptCatalog> _logger;
    private readonly string _absRoot;

    public BashScriptCatalog(IOptions<BashScriptCatalogOptions> opts, ILogger<BashScriptCatalog> logger)
    {
        _opts = opts.Value;
        _logger = logger;
        _absRoot = Path.GetFullPath(_opts.Root);
    }

    public Task<IReadOnlyList<BashScriptEntry>> ListAsync(CancellationToken ct = default)
    {
        if (!Directory.Exists(_absRoot))
        {
            _logger.LogWarning("BashScript catalog root does not exist: {Root}", _absRoot);
            return Task.FromResult<IReadOnlyList<BashScriptEntry>>(Array.Empty<BashScriptEntry>());
        }

        var entries = new DirectoryInfo(_absRoot)
            .EnumerateFiles("*", SearchOption.TopDirectoryOnly)
            .OrderBy(f => f.Name, StringComparer.OrdinalIgnoreCase)
            .Select(f => new BashScriptEntry(
                Name: f.Name,
                RelativePath: Path.GetRelativePath(_absRoot, f.FullName),
                SizeBytes: f.Length,
                LastModified: f.LastWriteTimeUtc,
                Kind: ClassifyKind(f.Name)))
            .ToList();

        return Task.FromResult<IReadOnlyList<BashScriptEntry>>(entries);
    }

    public async Task<string?> ReadAsync(string name, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;

        // Path-traversal guard: resolve and confirm it stays inside _absRoot.
        var requested = Path.GetFullPath(Path.Combine(_absRoot, name));
        if (!requested.StartsWith(_absRoot + Path.DirectorySeparatorChar, StringComparison.Ordinal)
            && !string.Equals(requested, _absRoot, StringComparison.Ordinal))
        {
            _logger.LogWarning("BashScript read rejected — path escapes root: requested={Requested} root={Root}", requested, _absRoot);
            return null;
        }

        if (!File.Exists(requested)) return null;

        var info = new FileInfo(requested);
        if (info.Length > _opts.MaxFileSizeBytes)
        {
            return $"# File too large to display ({info.Length:N0} bytes; cap is {_opts.MaxFileSizeBytes:N0}).";
        }

        return await File.ReadAllTextAsync(requested, ct);
    }

    private static string ClassifyKind(string name) => Path.GetExtension(name).ToLowerInvariant() switch
    {
        ".sh"      => "shell",
        ".conf"    => "nftables",
        ".txt"     => "text",
        ".sql"     => "sql",
        _          => "other"
    };
}
