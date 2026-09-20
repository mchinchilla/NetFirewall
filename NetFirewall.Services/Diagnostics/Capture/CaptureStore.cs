using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NetFirewall.Services.Diagnostics.Capture;

/// <summary>
/// Capture files live under the daemon's state directory
/// (<c>/var/lib/netfirewall/daemon/captures</c>). That path is deliberate: it is
/// the only writable location in the unit's <c>ProtectSystem=strict</c> sandbox
/// that survives, and <c>PrivateTmp=yes</c> means anything under /tmp would be
/// invisible to the rest of the system. Names are job GUIDs, so a request can
/// never name a file.
/// </summary>
public sealed class CaptureStore : ICaptureStore
{
    private readonly DiagnosticsOptions _opts;
    private readonly ILogger<CaptureStore> _logger;

    public CaptureStore(IOptions<DiagnosticsOptions> opts, ILogger<CaptureStore> logger)
    {
        _opts = opts.Value;
        _logger = logger;
    }

    public string PathFor(Guid jobId)
    {
        Directory.CreateDirectory(_opts.CaptureDirectory);
        return Path.Combine(_opts.CaptureDirectory, jobId.ToString("N") + ".pcap");
    }

    public Stream? OpenRead(Guid jobId)
    {
        var path = Path.Combine(_opts.CaptureDirectory, jobId.ToString("N") + ".pcap");
        if (!File.Exists(path)) return null;
        try { return File.Open(path, new FileStreamOptions { Mode = FileMode.Open, Access = FileAccess.Read, Share = FileShare.Read, Options = FileOptions.Asynchronous }); }
        catch (Exception ex) { _logger.LogWarning(ex, "Could not open capture {Id}", jobId); return null; }
    }

    public bool Delete(Guid jobId)
    {
        var path = Path.Combine(_opts.CaptureDirectory, jobId.ToString("N") + ".pcap");
        try
        {
            if (!File.Exists(path)) return false;
            File.Delete(path);
            return true;
        }
        catch (Exception ex) { _logger.LogWarning(ex, "Could not delete capture {Id}", jobId); return false; }
    }

    public int PurgeOlderThan(TimeSpan age)
    {
        if (!Directory.Exists(_opts.CaptureDirectory)) return 0;
        var cutoff = DateTime.UtcNow - age;
        var removed = 0;
        foreach (var file in Directory.EnumerateFiles(_opts.CaptureDirectory, "*.pcap"))
        {
            try
            {
                if (File.GetLastWriteTimeUtc(file) >= cutoff) continue;
                File.Delete(file);
                removed++;
            }
            catch (Exception ex) { _logger.LogDebug(ex, "Could not purge {File}", file); }
        }
        if (removed > 0) _logger.LogInformation("Purged {Count} capture file(s) older than {Age}", removed, age);
        return removed;
    }

    public long TotalBytes()
    {
        if (!Directory.Exists(_opts.CaptureDirectory)) return 0;
        try { return Directory.EnumerateFiles(_opts.CaptureDirectory, "*.pcap").Sum(f => new FileInfo(f).Length); }
        catch { return 0; }
    }
}
