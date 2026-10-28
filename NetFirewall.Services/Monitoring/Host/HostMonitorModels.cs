namespace NetFirewall.Services.Monitoring.Host;

/// <summary>
/// One second of the host as the kernel counts it. CPU fractions are of the
/// whole machine (0..1, all cores together); rates are bytes per second.
/// </summary>
/// <param name="CpuUser">user + nice.</param>
/// <param name="CpuSystem">system + irq + softirq — on a firewall this is where packet forwarding shows up.</param>
/// <param name="CpuIoWait">Waiting on disk: not work, but it gives away a disk that can't keep up.</param>
/// <param name="MemoryUsed">Total minus available: what the kernel can't hand back without swapping.</param>
/// <param name="MemoryCache">Buffers + page cache: occupied, but released the moment someone asks.</param>
public readonly record struct HostSample(
    DateTimeOffset Time,
    double CpuUser,
    double CpuSystem,
    double CpuIoWait,
    long MemoryUsed,
    long MemoryCache,
    long SwapUsed,
    double Load1,
    double Load5,
    double Load15,
    double DiskReadBytesPerSecond,
    double DiskWriteBytesPerSecond,
    double NetworkInBytesPerSecond,
    double NetworkOutBytesPerSecond)
{
    public double CpuBusy => CpuUser + CpuSystem + CpuIoWait;

    public double DiskBytesPerSecond => DiskReadBytesPerSecond + DiskWriteBytesPerSecond;

    public double NetworkBytesPerSecond => NetworkInBytesPerSecond + NetworkOutBytesPerSecond;
}

/// <summary>What doesn't change from one second to the next: which machine this is.</summary>
/// <param name="OperatingSystem"><c>PRETTY_NAME</c> from <c>/etc/os-release</c>, when readable.</param>
public sealed record HostIdentity(
    string HostName,
    string? OperatingSystem,
    string? Kernel,
    string? CpuModel,
    int Cores,
    long MemoryTotal,
    long SwapTotal,
    DateTimeOffset? BootedOn);

/// <summary>All processes of one program added up (postgres backends, nginx workers…).</summary>
/// <param name="CpuShare">Fraction of the whole machine, like <see cref="HostSample.CpuUser"/>.</param>
public sealed record HostProcessGroup(string Name, int Instances, double CpuShare, long ResidentBytes)
{
    /// <summary>Kernel threads (kworker, ksoftirqd…) share one row: each has its own name and they'd flood the list.</summary>
    public const string KernelThreads = "[kernel]";
}

public sealed record HostFilesystem(string MountPoint, string Format, long TotalBytes, long FreeBytes)
{
    public long UsedBytes => TotalBytes - FreeBytes;
}

/// <summary>What watching costs: the monitor has to prove it stays out of the way.</summary>
/// <param name="SampleMicroseconds">Moving average of one system sample, in µs.</param>
/// <param name="ProcessScanMicroseconds">The last process walk, in µs.</param>
/// <param name="HistoryBytes">Memory held by the hour of samples.</param>
public sealed record HostMonitorCost(
    int SampleSeconds,
    int ProcessScanSeconds,
    double SampleMicroseconds,
    double ProcessScanMicroseconds,
    long HistoryBytes);

/// <param name="Samples">Oldest first.</param>
public sealed record HostMonitorState(
    HostIdentity Identity,
    IReadOnlyList<HostSample> Samples,
    IReadOnlyList<HostProcessGroup> Processes,
    IReadOnlyList<HostFilesystem> Filesystems,
    HostMonitorCost Cost);

/// <summary>
/// The host monitor: <c>/proc</c> sampled every second, the last hour kept in
/// memory. It talks to nothing else — no database, no daemon — so looking at
/// it costs the firewall nothing.
/// </summary>
public interface IHostMonitor
{
    /// <summary>Samples since <paramref name="since"/>, or null when this machine has no <c>/proc</c>.</summary>
    HostMonitorState? Snapshot(DateTimeOffset since);
}

/// <summary>
/// The monitor over one window. Both series cover the same window with a
/// different column count — wide cards (CPU, memory) and narrow ones (load,
/// disk, network) — so a dot measures the same span of time in both.
/// </summary>
/// <param name="Current">The latest sample, or null before the first one.</param>
/// <param name="Wide">One entry per column; null where that slice had no samples.</param>
public sealed record HostMonitorView(
    HostIdentity Identity,
    HostSample? Current,
    int WindowSeconds,
    IReadOnlyList<HostSample?> Wide,
    IReadOnlyList<HostSample?> Narrow,
    IReadOnlyList<HostProcessGroup> Processes,
    IReadOnlyList<HostFilesystem> Filesystems,
    HostMonitorCost Cost,
    DateTimeOffset CheckedOn);

/// <summary>The window selector. Anything else in the URL falls back to one minute.</summary>
public static class HostWindows
{
    public const int Default = 60;

    /// <summary>The dashboard / Monitoring strip always shows five minutes.</summary>
    public const int Strip = 300;

    public static readonly IReadOnlyList<int> All = [60, 300, 900, 3600];

    public static int Clean(int? seconds) => seconds is { } value && All.Contains(value) ? value : Default;
}

/// <summary>Buckets samples into the dot-matrix columns.</summary>
public static class HostTimeline
{
    public const int WideColumns = 60;
    public const int NarrowColumns = 40;

    /// <summary>
    /// Right-closed columns ending at <paramref name="end"/>: the last one is
    /// <c>(end - width, end]</c>, so the sample taken at <paramref name="end"/> lands in it.
    /// </summary>
    public static IReadOnlyList<HostSample?> Columns(IReadOnlyList<HostSample> samples, DateTimeOffset end, TimeSpan window, int count)
    {
        ArgumentNullException.ThrowIfNull(samples);
        ArgumentOutOfRangeException.ThrowIfLessThan(count, 1);

        var start = end - window;
        var width = window.TotalSeconds / count;
        var sums = new Accumulator[count];

        foreach (var sample in samples)
        {
            if (sample.Time <= start || sample.Time > end) continue;

            var index = Math.Clamp((int)Math.Ceiling((sample.Time - start).TotalSeconds / width) - 1, 0, count - 1);
            sums[index].Add(sample);
        }

        var columns = new HostSample?[count];
        for (var i = 0; i < count; i++)
        {
            columns[i] = sums[i].Average();
        }

        // A lone gap between two full columns is timer drift against the column
        // edge, not the host: repeat the previous one. Two in a row is a real gap.
        for (var i = 1; i < count - 1; i++)
        {
            if (columns[i] is null && columns[i - 1] is not null && columns[i + 1] is not null)
            {
                columns[i] = columns[i - 1];
            }
        }

        return columns;
    }

    private struct Accumulator
    {
        private int _count;
        private DateTimeOffset _last;
        private double _user, _system, _ioWait, _used, _cache, _swap, _load1, _load5, _load15, _read, _write, _in, _out;

        public void Add(HostSample sample)
        {
            _count++;
            _last = sample.Time > _last ? sample.Time : _last;
            _user += sample.CpuUser;
            _system += sample.CpuSystem;
            _ioWait += sample.CpuIoWait;
            _used += sample.MemoryUsed;
            _cache += sample.MemoryCache;
            _swap += sample.SwapUsed;
            _load1 += sample.Load1;
            _load5 += sample.Load5;
            _load15 += sample.Load15;
            _read += sample.DiskReadBytesPerSecond;
            _write += sample.DiskWriteBytesPerSecond;
            _in += sample.NetworkInBytesPerSecond;
            _out += sample.NetworkOutBytesPerSecond;
        }

        public readonly HostSample? Average()
        {
            if (_count == 0) return null;

            double n = _count;
            return new HostSample(
                _last,
                _user / n, _system / n, _ioWait / n,
                (long)(_used / n), (long)(_cache / n), (long)(_swap / n),
                _load1 / n, _load5 / n, _load15 / n,
                _read / n, _write / n, _in / n, _out / n);
        }
    }
}
