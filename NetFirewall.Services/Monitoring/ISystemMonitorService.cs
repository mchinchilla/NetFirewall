namespace NetFirewall.Services.Monitoring;

/// <summary>
/// Service for monitoring system resources (CPU, Memory, Disk, Network).
/// Optimized for Linux with /proc filesystem, with fallbacks for other platforms.
/// </summary>
public interface ISystemMonitorService
{
    /// <summary>
    /// Get current CPU usage metrics.
    /// </summary>
    Task<CpuMetrics> GetCpuMetricsAsync(CancellationToken ct = default);

    /// <summary>
    /// Get current memory usage metrics.
    /// </summary>
    Task<MemoryMetrics> GetMemoryMetricsAsync(CancellationToken ct = default);

    /// <summary>
    /// Get disk usage for all mounted filesystems.
    /// </summary>
    Task<IReadOnlyList<DiskMetrics>> GetDiskMetricsAsync(CancellationToken ct = default);

    /// <summary>
    /// Get network interface statistics.
    /// </summary>
    Task<IReadOnlyList<NetworkMetrics>> GetNetworkMetricsAsync(CancellationToken ct = default);

    /// <summary>
    /// Get system uptime and load averages.
    /// </summary>
    Task<SystemInfo> GetSystemInfoAsync(CancellationToken ct = default);

    /// <summary>
    /// Get all metrics in a single call (more efficient).
    /// </summary>
    Task<SystemMetricsSnapshot> GetSnapshotAsync(CancellationToken ct = default);
}

/// <summary>
/// CPU metrics from /proc/stat
/// </summary>
public record CpuMetrics
{
    public double UsagePercent { get; init; }
    public double UserPercent { get; init; }
    public double SystemPercent { get; init; }
    public double IoWaitPercent { get; init; }
    public double IdlePercent { get; init; }
    public int CoreCount { get; init; }
    public IReadOnlyList<double> PerCoreUsage { get; init; } = [];
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
}

/// <summary>
/// Memory metrics from /proc/meminfo
/// </summary>
public record MemoryMetrics
{
    public long TotalBytes { get; init; }
    public long UsedBytes { get; init; }
    public long FreeBytes { get; init; }
    public long AvailableBytes { get; init; }
    public long BuffersBytes { get; init; }
    public long CachedBytes { get; init; }
    public long SwapTotalBytes { get; init; }
    public long SwapUsedBytes { get; init; }
    public long SwapFreeBytes { get; init; }

    public double UsagePercent => TotalBytes > 0 ? (double)UsedBytes / TotalBytes * 100 : 0;
    public double SwapUsagePercent => SwapTotalBytes > 0 ? (double)SwapUsedBytes / SwapTotalBytes * 100 : 0;

    public string TotalFormatted => FormatBytes(TotalBytes);
    public string UsedFormatted => FormatBytes(UsedBytes);
    public string FreeFormatted => FormatBytes(FreeBytes);
    public string AvailableFormatted => FormatBytes(AvailableBytes);

    private static string FormatBytes(long bytes)
    {
        string[] sizes = ["B", "KB", "MB", "GB", "TB"];
        int order = 0;
        double size = bytes;
        while (size >= 1024 && order < sizes.Length - 1)
        {
            order++;
            size /= 1024;
        }
        return $"{size:0.##} {sizes[order]}";
    }
}

/// <summary>
/// Disk metrics from df/statvfs
/// </summary>
public record DiskMetrics
{
    public string Device { get; init; } = "";
    public string MountPoint { get; init; } = "";
    public string FileSystem { get; init; } = "";
    public long TotalBytes { get; init; }
    public long UsedBytes { get; init; }
    public long FreeBytes { get; init; }
    public double UsagePercent => TotalBytes > 0 ? (double)UsedBytes / TotalBytes * 100 : 0;

    public string TotalFormatted => FormatBytes(TotalBytes);
    public string UsedFormatted => FormatBytes(UsedBytes);
    public string FreeFormatted => FormatBytes(FreeBytes);

    private static string FormatBytes(long bytes)
    {
        string[] sizes = ["B", "KB", "MB", "GB", "TB"];
        int order = 0;
        double size = bytes;
        while (size >= 1024 && order < sizes.Length - 1)
        {
            order++;
            size /= 1024;
        }
        return $"{size:0.##} {sizes[order]}";
    }
}

/// <summary>
/// Network interface metrics from /proc/net/dev
/// </summary>
public record NetworkMetrics
{
    public string InterfaceName { get; init; } = "";
    public long BytesReceived { get; init; }
    public long BytesSent { get; init; }
    public long PacketsReceived { get; init; }
    public long PacketsSent { get; init; }
    public long ErrorsReceived { get; init; }
    public long ErrorsSent { get; init; }
    public long DropsReceived { get; init; }
    public long DropsSent { get; init; }

    // Calculated rates (requires two samples)
    public double BytesReceivedPerSecond { get; init; }
    public double BytesSentPerSecond { get; init; }

    public string BytesReceivedFormatted => FormatBytes(BytesReceived);
    public string BytesSentFormatted => FormatBytes(BytesSent);

    private static string FormatBytes(long bytes)
    {
        string[] sizes = ["B", "KB", "MB", "GB", "TB"];
        int order = 0;
        double size = bytes;
        while (size >= 1024 && order < sizes.Length - 1)
        {
            order++;
            size /= 1024;
        }
        return $"{size:0.##} {sizes[order]}";
    }
}

/// <summary>
/// System information
/// </summary>
public record SystemInfo
{
    public string Hostname { get; init; } = "";
    public string KernelVersion { get; init; } = "";
    public string OsName { get; init; } = "";
    public TimeSpan Uptime { get; init; }
    public double LoadAverage1Min { get; init; }
    public double LoadAverage5Min { get; init; }
    public double LoadAverage15Min { get; init; }
    public int ProcessCount { get; init; }
    public DateTime BootTime { get; init; }
}

/// <summary>
/// Complete system metrics snapshot
/// </summary>
public record SystemMetricsSnapshot
{
    public CpuMetrics Cpu { get; init; } = new();
    public MemoryMetrics Memory { get; init; } = new();
    public IReadOnlyList<DiskMetrics> Disks { get; init; } = [];
    public IReadOnlyList<NetworkMetrics> Network { get; init; } = [];
    public SystemInfo System { get; init; } = new();
    public DateTime Timestamp { get; init; } = DateTime.UtcNow;
}
