using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

namespace NetFirewall.Services.Monitoring;

/// <summary>
/// High-performance system monitor service.
/// Uses /proc filesystem on Linux for efficient metric collection.
/// </summary>
public sealed class SystemMonitorService : ISystemMonitorService
{
    private readonly ILogger<SystemMonitorService> _logger;
    private readonly bool _isLinux;

    // CPU state tracking for percentage calculation
    private readonly ConcurrentDictionary<string, CpuSample> _lastCpuSamples = new();

    // Network state tracking for rate calculation
    private readonly ConcurrentDictionary<string, NetworkSample> _lastNetworkSamples = new();

    public SystemMonitorService(ILogger<SystemMonitorService> logger)
    {
        _logger = logger;
        _isLinux = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
    }

    public async Task<SystemMetricsSnapshot> GetSnapshotAsync(CancellationToken ct = default)
    {
        var cpuTask = GetCpuMetricsAsync(ct);
        var memoryTask = GetMemoryMetricsAsync(ct);
        var diskTask = GetDiskMetricsAsync(ct);
        var networkTask = GetNetworkMetricsAsync(ct);
        var systemTask = GetSystemInfoAsync(ct);

        await Task.WhenAll(cpuTask, memoryTask, diskTask, networkTask, systemTask);

        return new SystemMetricsSnapshot
        {
            Cpu = await cpuTask,
            Memory = await memoryTask,
            Disks = await diskTask,
            Network = await networkTask,
            System = await systemTask,
            Timestamp = DateTime.UtcNow
        };
    }

    #region CPU Metrics

    public async Task<CpuMetrics> GetCpuMetricsAsync(CancellationToken ct = default)
    {
        if (!_isLinux)
        {
            return GetCpuMetricsFallback();
        }

        try
        {
            var lines = await File.ReadAllLinesAsync("/proc/stat", ct);
            var cpuLines = lines.Where(l => l.StartsWith("cpu")).ToList();

            var perCoreUsage = new List<double>();
            double totalUser = 0, totalSystem = 0, totalIdle = 0, totalIoWait = 0, totalUsage = 0;

            foreach (var line in cpuLines)
            {
                var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 8) continue;

                var cpuName = parts[0];
                var user = long.Parse(parts[1]);
                var nice = long.Parse(parts[2]);
                var system = long.Parse(parts[3]);
                var idle = long.Parse(parts[4]);
                var iowait = long.Parse(parts[5]);
                var irq = long.Parse(parts[6]);
                var softirq = long.Parse(parts[7]);
                var steal = parts.Length > 8 ? long.Parse(parts[8]) : 0;

                var total = user + nice + system + idle + iowait + irq + softirq + steal;
                var active = total - idle - iowait;

                // Get previous sample
                var usage = 0.0;
                if (_lastCpuSamples.TryGetValue(cpuName, out var lastSample))
                {
                    var deltaTotal = total - lastSample.Total;
                    var deltaActive = active - lastSample.Active;
                    if (deltaTotal > 0)
                    {
                        usage = (double)deltaActive / deltaTotal * 100;
                    }
                }

                // Update sample
                _lastCpuSamples[cpuName] = new CpuSample(total, active, DateTime.UtcNow);

                if (cpuName == "cpu")
                {
                    var deltaTotalMain = total;
                    if (_lastCpuSamples.TryGetValue("cpu_prev", out var prev))
                    {
                        deltaTotalMain = total - prev.Total;
                        if (deltaTotalMain > 0)
                        {
                            totalUser = (double)(user + nice - (prev.Active > 0 ? 0 : 0)) / deltaTotalMain * 100;
                            totalSystem = (double)(system + irq + softirq) / deltaTotalMain * 100;
                            totalIdle = (double)idle / deltaTotalMain * 100;
                            totalIoWait = (double)iowait / deltaTotalMain * 100;
                        }
                    }
                    totalUsage = usage;
                }
                else
                {
                    perCoreUsage.Add(usage);
                }
            }

            return new CpuMetrics
            {
                UsagePercent = Math.Round(totalUsage, 2),
                UserPercent = Math.Round(totalUser, 2),
                SystemPercent = Math.Round(totalSystem, 2),
                IoWaitPercent = Math.Round(totalIoWait, 2),
                IdlePercent = Math.Round(totalIdle, 2),
                CoreCount = perCoreUsage.Count,
                PerCoreUsage = perCoreUsage,
                Timestamp = DateTime.UtcNow
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error reading CPU metrics from /proc/stat");
            return GetCpuMetricsFallback();
        }
    }

    private static CpuMetrics GetCpuMetricsFallback()
    {
        return new CpuMetrics
        {
            CoreCount = Environment.ProcessorCount,
            Timestamp = DateTime.UtcNow
        };
    }

    #endregion

    #region Memory Metrics

    public async Task<MemoryMetrics> GetMemoryMetricsAsync(CancellationToken ct = default)
    {
        if (!_isLinux)
        {
            return GetMemoryMetricsFallback();
        }

        try
        {
            var lines = await File.ReadAllLinesAsync("/proc/meminfo", ct);
            var memInfo = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);

            foreach (var line in lines)
            {
                var colonIndex = line.IndexOf(':');
                if (colonIndex < 0) continue;

                var key = line[..colonIndex].Trim();
                var valueStr = line[(colonIndex + 1)..].Trim();

                // Parse value (remove 'kB' suffix)
                var parts = valueStr.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length > 0 && long.TryParse(parts[0], out var value))
                {
                    // Convert from kB to bytes
                    memInfo[key] = value * 1024;
                }
            }

            var total = memInfo.GetValueOrDefault("MemTotal");
            var free = memInfo.GetValueOrDefault("MemFree");
            var available = memInfo.GetValueOrDefault("MemAvailable");
            var buffers = memInfo.GetValueOrDefault("Buffers");
            var cached = memInfo.GetValueOrDefault("Cached");
            var swapTotal = memInfo.GetValueOrDefault("SwapTotal");
            var swapFree = memInfo.GetValueOrDefault("SwapFree");

            // Calculate used memory (excluding buffers/cache)
            var used = total - available;

            return new MemoryMetrics
            {
                TotalBytes = total,
                UsedBytes = used,
                FreeBytes = free,
                AvailableBytes = available,
                BuffersBytes = buffers,
                CachedBytes = cached,
                SwapTotalBytes = swapTotal,
                SwapUsedBytes = swapTotal - swapFree,
                SwapFreeBytes = swapFree
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error reading memory metrics from /proc/meminfo");
            return GetMemoryMetricsFallback();
        }
    }

    private static MemoryMetrics GetMemoryMetricsFallback()
    {
        var gcInfo = GC.GetGCMemoryInfo();
        return new MemoryMetrics
        {
            TotalBytes = gcInfo.TotalAvailableMemoryBytes,
            UsedBytes = GC.GetTotalMemory(false),
            FreeBytes = gcInfo.TotalAvailableMemoryBytes - GC.GetTotalMemory(false),
            AvailableBytes = gcInfo.TotalAvailableMemoryBytes - GC.GetTotalMemory(false)
        };
    }

    #endregion

    #region Disk Metrics

    public async Task<IReadOnlyList<DiskMetrics>> GetDiskMetricsAsync(CancellationToken ct = default)
    {
        if (!_isLinux)
        {
            return GetDiskMetricsFallback();
        }

        try
        {
            // Read /proc/mounts to get mounted filesystems
            var mountLines = await File.ReadAllLinesAsync("/proc/mounts", ct);
            var disks = new List<DiskMetrics>();

            foreach (var line in mountLines)
            {
                var parts = line.Split(' ');
                if (parts.Length < 4) continue;

                var device = parts[0];
                var mountPoint = parts[1];
                var fsType = parts[2];

                // Skip virtual filesystems
                if (fsType is "proc" or "sysfs" or "devpts" or "tmpfs" or "cgroup" or "cgroup2"
                    or "securityfs" or "pstore" or "debugfs" or "configfs" or "fusectl"
                    or "hugetlbfs" or "mqueue" or "bpf" or "overlay" or "nsfs")
                {
                    continue;
                }

                // Skip devices that don't start with /dev
                if (!device.StartsWith("/dev/"))
                {
                    continue;
                }

                try
                {
                    var driveInfo = new DriveInfo(mountPoint);
                    if (driveInfo.IsReady)
                    {
                        disks.Add(new DiskMetrics
                        {
                            Device = device,
                            MountPoint = mountPoint,
                            FileSystem = fsType,
                            TotalBytes = driveInfo.TotalSize,
                            UsedBytes = driveInfo.TotalSize - driveInfo.AvailableFreeSpace,
                            FreeBytes = driveInfo.AvailableFreeSpace
                        });
                    }
                }
                catch
                {
                    // Skip if we can't get drive info
                }
            }

            return disks;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error reading disk metrics");
            return GetDiskMetricsFallback();
        }
    }

    private static IReadOnlyList<DiskMetrics> GetDiskMetricsFallback()
    {
        var disks = new List<DiskMetrics>();

        foreach (var drive in DriveInfo.GetDrives())
        {
            if (drive.IsReady && drive.DriveType == DriveType.Fixed)
            {
                disks.Add(new DiskMetrics
                {
                    Device = drive.Name,
                    MountPoint = drive.RootDirectory.FullName,
                    FileSystem = drive.DriveFormat,
                    TotalBytes = drive.TotalSize,
                    UsedBytes = drive.TotalSize - drive.AvailableFreeSpace,
                    FreeBytes = drive.AvailableFreeSpace
                });
            }
        }

        return disks;
    }

    #endregion

    #region Network Metrics

    public async Task<IReadOnlyList<NetworkMetrics>> GetNetworkMetricsAsync(CancellationToken ct = default)
    {
        if (!_isLinux)
        {
            return GetNetworkMetricsFallback();
        }

        try
        {
            var lines = await File.ReadAllLinesAsync("/proc/net/dev", ct);
            var metrics = new List<NetworkMetrics>();
            var now = DateTime.UtcNow;

            // Skip first two header lines
            foreach (var line in lines.Skip(2))
            {
                var colonIndex = line.IndexOf(':');
                if (colonIndex < 0) continue;

                var ifaceName = line[..colonIndex].Trim();
                var values = line[(colonIndex + 1)..]
                    .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                    .Select(long.Parse)
                    .ToArray();

                if (values.Length < 16) continue;

                // Values order: bytes, packets, errs, drop, fifo, frame, compressed, multicast (RX)
                //               bytes, packets, errs, drop, fifo, colls, carrier, compressed (TX)
                var rxBytes = values[0];
                var rxPackets = values[1];
                var rxErrors = values[2];
                var rxDrops = values[3];
                var txBytes = values[8];
                var txPackets = values[9];
                var txErrors = values[10];
                var txDrops = values[11];

                // Calculate rates
                double rxRate = 0, txRate = 0;
                if (_lastNetworkSamples.TryGetValue(ifaceName, out var lastSample))
                {
                    var elapsed = (now - lastSample.Timestamp).TotalSeconds;
                    if (elapsed > 0)
                    {
                        rxRate = (rxBytes - lastSample.BytesReceived) / elapsed;
                        txRate = (txBytes - lastSample.BytesSent) / elapsed;
                    }
                }

                // Update sample
                _lastNetworkSamples[ifaceName] = new NetworkSample(rxBytes, txBytes, now);

                metrics.Add(new NetworkMetrics
                {
                    InterfaceName = ifaceName,
                    BytesReceived = rxBytes,
                    BytesSent = txBytes,
                    PacketsReceived = rxPackets,
                    PacketsSent = txPackets,
                    ErrorsReceived = rxErrors,
                    ErrorsSent = txErrors,
                    DropsReceived = rxDrops,
                    DropsSent = txDrops,
                    BytesReceivedPerSecond = Math.Max(0, rxRate),
                    BytesSentPerSecond = Math.Max(0, txRate)
                });
            }

            return metrics;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error reading network metrics from /proc/net/dev");
            return GetNetworkMetricsFallback();
        }
    }

    private static IReadOnlyList<NetworkMetrics> GetNetworkMetricsFallback()
    {
        var metrics = new List<NetworkMetrics>();

        foreach (var iface in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
        {
            if (iface.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up)
                continue;

            try
            {
                var stats = iface.GetIPStatistics();

                // Some properties throw PlatformNotSupportedException on macOS/BSD
                metrics.Add(new NetworkMetrics
                {
                    InterfaceName = iface.Name,
                    BytesReceived = stats.BytesReceived,
                    BytesSent = stats.BytesSent,
                    PacketsReceived = stats.UnicastPacketsReceived,
                    PacketsSent = stats.UnicastPacketsSent,
                    ErrorsReceived = SafeGetStat(() => stats.IncomingPacketsWithErrors),
                    ErrorsSent = SafeGetStat(() => stats.OutgoingPacketsWithErrors),
                    DropsReceived = SafeGetStat(() => stats.IncomingPacketsDiscarded),
                    DropsSent = SafeGetStat(() => stats.OutgoingPacketsDiscarded)
                });
            }
            catch (PlatformNotSupportedException)
            {
                // Skip interfaces that don't support statistics on this platform
            }
        }

        return metrics;
    }

    private static long SafeGetStat(Func<long> getter)
    {
        try
        {
            return getter();
        }
        catch (PlatformNotSupportedException)
        {
            return 0;
        }
    }

    #endregion

    #region System Info

    public async Task<SystemInfo> GetSystemInfoAsync(CancellationToken ct = default)
    {
        var hostname = Environment.MachineName;
        var osName = RuntimeInformation.OSDescription;
        var kernelVersion = "";
        var uptime = TimeSpan.Zero;
        var load1 = 0.0;
        var load5 = 0.0;
        var load15 = 0.0;
        var processCount = 0;

        if (_isLinux)
        {
            try
            {
                // Read uptime
                var uptimeContent = await File.ReadAllTextAsync("/proc/uptime", ct);
                var uptimeParts = uptimeContent.Split(' ');
                if (uptimeParts.Length > 0 && double.TryParse(uptimeParts[0], out var uptimeSeconds))
                {
                    uptime = TimeSpan.FromSeconds(uptimeSeconds);
                }

                // Read load average
                var loadContent = await File.ReadAllTextAsync("/proc/loadavg", ct);
                var loadParts = loadContent.Split(' ');
                if (loadParts.Length >= 3)
                {
                    double.TryParse(loadParts[0], out load1);
                    double.TryParse(loadParts[1], out load5);
                    double.TryParse(loadParts[2], out load15);
                }
                if (loadParts.Length >= 4)
                {
                    var procParts = loadParts[3].Split('/');
                    if (procParts.Length >= 2)
                    {
                        int.TryParse(procParts[1], out processCount);
                    }
                }

                // Read kernel version
                if (File.Exists("/proc/version"))
                {
                    var versionContent = await File.ReadAllTextAsync("/proc/version", ct);
                    var versionParts = versionContent.Split(' ');
                    if (versionParts.Length >= 3)
                    {
                        kernelVersion = versionParts[2];
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error reading system info from /proc");
            }
        }
        else
        {
            uptime = TimeSpan.FromMilliseconds(Environment.TickCount64);
            processCount = Process.GetProcesses().Length;
        }

        return new SystemInfo
        {
            Hostname = hostname,
            KernelVersion = kernelVersion,
            OsName = osName,
            Uptime = uptime,
            LoadAverage1Min = load1,
            LoadAverage5Min = load5,
            LoadAverage15Min = load15,
            ProcessCount = processCount,
            BootTime = DateTime.UtcNow - uptime
        };
    }

    #endregion

    #region Sample Records

    private record CpuSample(long Total, long Active, DateTime Timestamp);
    private record NetworkSample(long BytesReceived, long BytesSent, DateTime Timestamp);

    #endregion
}