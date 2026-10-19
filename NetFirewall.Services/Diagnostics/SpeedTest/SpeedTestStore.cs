using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics.SpeedTest;

/// <inheritdoc />
public sealed class SpeedTestStore : ISpeedTestStore
{
    private const string PayloadExt = ".bin";
    private const string MetaExt = ".json";
    private const string PartExt = ".part";

    /// <summary>A payload/metadata half younger than this may still be mid-commit; the periodic sweep leaves it alone.</summary>
    private static readonly TimeSpan OrphanGrace = TimeSpan.FromMinutes(10);

    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    private readonly DiagnosticsOptions _opts;
    private readonly ILogger<SpeedTestStore> _logger;

    public SpeedTestStore(IOptions<DiagnosticsOptions> opts, ILogger<SpeedTestStore> logger)
    {
        _opts = opts.Value;
        _logger = logger;
    }

    private string Dir => _opts.SpeedTestDirectory;
    private string PathOf(Guid id, string ext) => Path.Combine(Dir, id.ToString("N") + ext);

    public string PartPathFor(Guid id)
    {
        Directory.CreateDirectory(Dir);
        return PathOf(id, PartExt);
    }

    public async Task CommitAsync(SpeedTestFile meta, CancellationToken ct = default)
    {
        File.Move(PathOf(meta.Id, PartExt), PathOf(meta.Id, PayloadExt), overwrite: true);
        // Metadata last: a payload without it is an orphan the sweeper reaps, never a
        // listed file with an unknown expiry.
        await using var fs = File.Create(PathOf(meta.Id, MetaExt));
        await JsonSerializer.SerializeAsync(fs, meta, Json, ct);
    }

    public void Discard(Guid id) => TryDelete(PathOf(id, PartExt));

    public async Task<IReadOnlyList<SpeedTestFile>> ListAsync(CancellationToken ct = default)
    {
        if (!Directory.Exists(Dir)) return Array.Empty<SpeedTestFile>();
        var now = DateTime.UtcNow;
        var list = new List<SpeedTestFile>();
        foreach (var metaPath in Directory.EnumerateFiles(Dir, "*" + MetaExt))
        {
            var meta = await ReadMetaAsync(metaPath, ct);
            if (meta is null || meta.IsExpired(now) || !File.Exists(PathOf(meta.Id, PayloadExt))) continue;
            list.Add(meta);
        }
        return list.OrderByDescending(m => m.CreatedAtUtc).ToList();
    }

    public async Task<SpeedTestFile?> GetAsync(Guid id, CancellationToken ct = default)
    {
        var meta = await ReadMetaAsync(PathOf(id, MetaExt), ct);
        return meta is null || meta.IsExpired(DateTime.UtcNow) || !File.Exists(PathOf(id, PayloadExt)) ? null : meta;
    }

    public async Task<(SpeedTestFile Meta, Stream Content)?> OpenReadAsync(Guid id, CancellationToken ct = default)
    {
        var meta = await GetAsync(id, ct);
        if (meta is null) return null;
        try
        {
            var stream = File.Open(PathOf(id, PayloadExt), new FileStreamOptions
            {
                Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.Read | FileShare.Delete,
                Options = FileOptions.Asynchronous | FileOptions.SequentialScan,
            });
            return (meta, stream);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not open speed-test file {Id}", id);
            return null;
        }
    }

    public bool Delete(Guid id)
    {
        var existed = File.Exists(PathOf(id, PayloadExt)) || File.Exists(PathOf(id, MetaExt));
        TryDelete(PathOf(id, PayloadExt));
        TryDelete(PathOf(id, MetaExt));
        return existed;
    }

    public async Task<int> SweepAsync(bool includeInProgress, CancellationToken ct = default)
    {
        if (!Directory.Exists(Dir)) return 0;
        var now = DateTime.UtcNow;
        var removed = 0;

        foreach (var path in Directory.EnumerateFiles(Dir).ToList())
        {
            ct.ThrowIfCancellationRequested();
            var ext = Path.GetExtension(path);
            if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(path), "N", out var id))
                continue;   // not ours — never delete what we did not name

            var settled = now - File.GetLastWriteTimeUtc(path) > OrphanGrace;
            var drop = ext switch
            {
                PartExt    => includeInProgress,
                PayloadExt => settled && !File.Exists(PathOf(id, MetaExt)),
                // An unreadable one may be mid-write; only a settled one is junk.
                MetaExt    => (await ReadMetaAsync(path, ct)) is { } meta
                              ? meta.IsExpired(now) || (settled && !File.Exists(PathOf(id, PayloadExt)))
                              : settled,
                _          => false,
            };
            if (!drop) continue;

            if (ext == MetaExt) TryDelete(PathOf(id, PayloadExt));
            if (TryDelete(path)) removed++;
        }

        if (removed > 0) _logger.LogInformation("Speed-test sweep removed {Count} expired or orphaned file(s)", removed);
        return removed;
    }

    public string? CheckCapacity(long bytes)
    {
        var quota = (long)_opts.SpeedTestQuotaMegabytes * 1_000_000;
        var used = TotalBytes();
        if (used + bytes > quota)
            return $"Keeping this file could exceed the speed-test quota ({used / 1_000_000} of {quota / 1_000_000} MB used). "
                   + "Delete a kept file, lower the size cap, or run without keeping the file.";

        try
        {
            Directory.CreateDirectory(Dir);
            if (FreeSpaceOf(Dir) is not { } free) return null;
            var reserve = (long)_opts.SpeedTestFreeSpaceReserveMegabytes * 1_000_000;
            if (free - bytes < reserve)
                return $"Not enough free disk space to keep the file ({free / 1_000_000} MB free, "
                       + $"{(bytes + reserve) / 1_000_000} MB needed including the {reserve / 1_000_000} MB reserve).";
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Free-space check skipped for {Dir}", Dir);
        }
        return null;
    }

    private long TotalBytes()
    {
        if (!Directory.Exists(Dir)) return 0;
        try
        {
            return Directory.EnumerateFiles(Dir)
                .Where(f => Path.GetExtension(f) is PayloadExt or PartExt)
                .Sum(f => new FileInfo(f).Length);
        }
        catch { return 0; }
    }

    /// <summary>
    /// Free bytes on the mount that holds <paramref name="dir"/> — longest mount-point
    /// prefix wins, so a separate /var is measured, not the root filesystem.
    /// </summary>
    private static long? FreeSpaceOf(string dir)
    {
        var full = Path.GetFullPath(dir);
        var best = DriveInfo.GetDrives()
            .Where(d => d.IsReady && full.StartsWith(d.RootDirectory.FullName, StringComparison.Ordinal))
            .MaxBy(d => d.RootDirectory.FullName.Length);
        return best?.AvailableFreeSpace;
    }

    private async Task<SpeedTestFile?> ReadMetaAsync(string path, CancellationToken ct)
    {
        if (!File.Exists(path)) return null;
        try
        {
            await using var fs = File.OpenRead(path);
            return await JsonSerializer.DeserializeAsync<SpeedTestFile>(fs, Json, ct);
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            _logger.LogDebug(ex, "Unreadable speed-test metadata {Path}", path);
            return null;
        }
    }

    private bool TryDelete(string path)
    {
        try
        {
            if (!File.Exists(path)) return false;
            File.Delete(path);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not delete {Path}", path);
            return false;
        }
    }
}
