using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Win32.SafeHandles;

namespace NetFirewall.Services.Monitoring.Host;

/// <summary>Where the host monitor reads from (section <c>HostMonitor</c>).</summary>
public sealed class HostMonitorOptions
{
    public const string SectionName = "HostMonitor";

    /// <summary>Off samples nothing and the page says so.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// The <c>/proc</c> to read. On the firewall it's the real one; a Mac has none,
    /// so for a dev box point this at a live copy of a container's.
    /// </summary>
    public string ProcRoot { get; set; } = "/proc";
}

/// <summary>The sampling loop the hosted service drives.</summary>
public interface IHostMetricsSampler
{
    /// <summary>One sample per second until <paramref name="cancellationToken"/> fires.</summary>
    Task RunAsync(CancellationToken cancellationToken);
}

/// <summary>
/// The host monitor. One <c>/proc</c> sample per second (CPU, memory, load, disk,
/// network) and a process walk every five, kept in memory: an hour of samples is
/// a few hundred KB and nothing goes to the database.
/// </summary>
/// <remarks>
/// What keeps it light: the six system files are opened once and re-read from
/// offset 0 (the kernel regenerates them on every read from the start, like
/// <c>top</c> does), into one shared buffer, parsed as bytes without decoding to
/// text. A sample costs on the order of a hundred microseconds and the page
/// shows what it really costs. Sampling and the process walk run on the same
/// loop, one after the other, because they share the buffer.
/// </remarks>
public sealed class HostMetricsSampler : IHostMonitor, IHostMetricsSampler, IDisposable
{
    public const int SampleSeconds = 1;
    public const int ProcessScanSeconds = 5;

    private const int HistorySeconds = 3600;
    private const int FilesystemSeconds = 30;
    private const int MaxFilesystems = 6;

    /// <summary>USER_HZ: /proc ticks are hundredths of a second on every user-space Linux.</summary>
    private const double ClockTicksPerSecond = 100;

    private readonly string _root;
    private readonly bool _available;
    private readonly ILogger<HostMetricsSampler> _logger;
    private readonly TimeProvider _time;
    private readonly byte[] _buffer = new byte[128 * 1024];
    private readonly Dictionary<string, SafeFileHandle> _handles = new(StringComparer.Ordinal);
    private readonly Dictionary<int, ProcessEntry> _pids = [];
    private readonly HashSet<int> _seen = [];

    private readonly Lock _gate = new();
    private readonly HostSample[] _ring = new HostSample[HistorySeconds];
    private int _next;
    private int _count;

    // What the previous sample read: rates are the difference.
    private bool _hasPrevious;
    private DateTimeOffset _previousOn;
    private CpuTimes _cpu;
    private long _diskRead, _diskWritten, _netIn, _netOut;
    private DateTimeOffset _lastScan;

    private string _hostName = Environment.MachineName;
    private string? _operatingSystem;
    private string? _kernel;
    private string? _cpuModel;
    private int _cores = Environment.ProcessorCount;
    private long _memoryTotal;
    private long _swapTotal;
    private DateTimeOffset? _bootedOn;
    private IReadOnlyList<HostProcessGroup> _processes = [];
    private IReadOnlyList<HostFilesystem> _filesystems = [];
    private double _sampleMicroseconds;
    private double _scanMicroseconds;
    private bool _failing;

    public HostMetricsSampler(IOptions<HostMonitorOptions> options, TimeProvider time, ILogger<HostMetricsSampler> logger)
    {
        ArgumentNullException.ThrowIfNull(options);

        _logger = logger;
        _time = time;
        _root = string.IsNullOrWhiteSpace(options.Value.ProcRoot) ? "/proc" : options.Value.ProcRoot;
        _available = options.Value.Enabled && File.Exists(Path.Combine(_root, "stat"));
    }

    public HostMonitorState? Snapshot(DateTimeOffset since)
    {
        if (!_available) return null;

        lock (_gate)
        {
            var samples = new List<HostSample>(_count);
            var first = (_next - _count + HistorySeconds) % HistorySeconds;
            for (var i = 0; i < _count; i++)
            {
                var sample = _ring[(first + i) % HistorySeconds];
                if (sample.Time >= since) samples.Add(sample);
            }

            return new HostMonitorState(
                new HostIdentity(_hostName, _operatingSystem, _kernel, _cpuModel, _cores, _memoryTotal, _swapTotal, _bootedOn),
                samples,
                _processes,
                _filesystems,
                new HostMonitorCost(
                    SampleSeconds, ProcessScanSeconds, _sampleMicroseconds, _scanMicroseconds,
                    (long)HistorySeconds * Unsafe.SizeOf<HostSample>()));
        }
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        if (!_available)
        {
            _logger.LogInformation("Host monitor off: no {ProcRoot} to read (or HostMonitor:Enabled is false)", _root);
            return;
        }

        await ReadIdentityAsync(cancellationToken);
        _logger.LogInformation("Host monitor reading {ProcRoot} on {HostName} ({Cores} cores)", _root, _hostName, _cores);

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(SampleSeconds), _time);
        long tick = 0;

        try
        {
            do
            {
                var now = _time.GetUtcNow();

                try
                {
                    var sampled = await SampleAsync(now, cancellationToken);
                    if (tick % ProcessScanSeconds == 0) await ScanProcessesAsync(now, cancellationToken);
                    if (tick % FilesystemSeconds == 0) await RefreshFilesystemsAsync(cancellationToken);

                    if (sampled && _failing)
                    {
                        _failing = false;
                        _logger.LogInformation("Host monitor reading {ProcRoot} again", _root);
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // Once per streak: an unreadable /proc must not flood the journal.
                    if (!_failing)
                    {
                        _failing = true;
                        _logger.LogWarning(ex, "Host monitor could not read {ProcRoot}; still trying", _root);
                    }
                }

                tick++;
            }
            while (await timer.WaitForNextTickAsync(cancellationToken));
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Host shutting down.
        }
    }

    /// <summary>
    /// One system sample. The first one only records the baseline: a rate needs
    /// two reads. False when CPU — the bare minimum — couldn't be read.
    /// </summary>
    public async Task<bool> SampleAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        if (!_available) return false;

        var started = Stopwatch.GetTimestamp();

        var read = await ReadSystemFileAsync("stat", cancellationToken);
        if (!ProcParser.TryParseCpu(_buffer.AsSpan(0, read), out var cpu, out var cores)) return false;

        // The rest is optional: a missing or unparsable file counts zero.
        read = await ReadSystemFileAsync("meminfo", cancellationToken);
        _ = ProcParser.TryParseMemory(_buffer.AsSpan(0, read), out var memory);

        read = await ReadSystemFileAsync("loadavg", cancellationToken);
        _ = ProcParser.TryParseLoad(_buffer.AsSpan(0, read), out var load1, out var load5, out var load15);

        read = await ReadSystemFileAsync("diskstats", cancellationToken);
        _ = ProcParser.TryParseDisks(_buffer.AsSpan(0, read), out var diskRead, out var diskWritten);

        read = await ReadSystemFileAsync("net/dev", cancellationToken);
        _ = ProcParser.TryParseNetwork(_buffer.AsSpan(0, read), out var netIn, out var netOut);

        read = await ReadSystemFileAsync("uptime", cancellationToken);
        var booted = ProcParser.TryParseUptime(_buffer.AsSpan(0, read), out var uptime);

        // A clock jumping backwards, or a long pause, gives no rate: start over.
        var elapsed = (now - _previousOn).TotalSeconds;
        HostSample? sample = null;
        if (_hasPrevious && elapsed is > 0 and < 30)
        {
            var total = cpu.Total - _cpu.Total;
            sample = new HostSample(
                now,
                Share(cpu.User - _cpu.User, total),
                Share(cpu.System - _cpu.System, total),
                Share(cpu.IoWait - _cpu.IoWait, total),
                memory.Used,
                memory.Cache,
                memory.SwapUsed,
                load1,
                load5,
                load15,
                Rate(diskRead, _diskRead, elapsed),
                Rate(diskWritten, _diskWritten, elapsed),
                Rate(netIn, _netIn, elapsed),
                Rate(netOut, _netOut, elapsed));
        }

        _hasPrevious = true;
        _previousOn = now;
        _cpu = cpu;
        (_diskRead, _diskWritten, _netIn, _netOut) = (diskRead, diskWritten, netIn, netOut);

        var cost = Stopwatch.GetElapsedTime(started).TotalMicroseconds;

        lock (_gate)
        {
            _cores = cores;
            _memoryTotal = memory.Total;
            _swapTotal = memory.SwapTotal;
            _bootedOn = booted ? now.AddSeconds(-uptime) : _bootedOn;
            _sampleMicroseconds = _sampleMicroseconds == 0 ? cost : (_sampleMicroseconds * 0.9) + (cost * 0.1);

            if (sample is { } value)
            {
                _ring[_next] = value;
                _next = (_next + 1) % HistorySeconds;
                _count = Math.Min(_count + 1, HistorySeconds);
            }
        }

        return true;
    }

    /// <summary>
    /// Processes grouped by name. Each one's CPU is what it spent since the
    /// previous walk; one seen for the first time counts zero, since we don't
    /// know since when.
    /// </summary>
    public async Task ScanProcessesAsync(DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        if (!_available) return;

        var started = Stopwatch.GetTimestamp();
        var elapsed = _lastScan == default ? 0 : (now - _lastScan).TotalSeconds;
        var capacity = ClockTicksPerSecond * elapsed * Math.Max(1, _cores);
        var groups = new Dictionary<string, (int Instances, long Ticks, long Pages)>(StringComparer.Ordinal);
        _seen.Clear();

        foreach (var directory in Directory.EnumerateDirectories(_root))
        {
            if (!int.TryParse(Path.GetFileName(directory.AsSpan()), NumberStyles.None, CultureInfo.InvariantCulture, out var pid)) continue;

            var read = await ReadOnceAsync(Path.Combine(directory, "stat"), cancellationToken);
            if (!ProcParser.TryParseProcess(_buffer.AsSpan(0, read), out var raw, out var ticks, out var pages, out var kernel)) continue;

            // The name is cached per pid so a walk doesn't allocate a string per
            // process. Ticks going down means the pid belongs to someone else now.
            long spent = 0;
            string name;
            if (_pids.TryGetValue(pid, out var known) && ticks >= known.Ticks && elapsed > 0)
            {
                name = known.Name;
                spent = ticks - known.Ticks;
            }
            else
            {
                name = kernel ? HostProcessGroup.KernelThreads : Encoding.UTF8.GetString(raw);
            }

            _pids[pid] = new ProcessEntry(name, ticks);
            _seen.Add(pid);

            groups[name] = groups.TryGetValue(name, out var group)
                ? (group.Instances + 1, group.Ticks + spent, group.Pages + pages)
                : (1, spent, pages);
        }

        foreach (var gone in _pids.Keys.Where(pid => !_seen.Contains(pid)).ToList())
        {
            _pids.Remove(gone);
        }

        long pageSize = Environment.SystemPageSize;
        HostProcessGroup[] processes =
        [
            .. groups.Select(pair => new HostProcessGroup(
                pair.Key,
                pair.Value.Instances,
                capacity > 0 ? Math.Clamp(pair.Value.Ticks / capacity, 0, 1) : 0,
                pair.Value.Pages * pageSize)),
        ];

        var cost = Stopwatch.GetElapsedTime(started).TotalMicroseconds;
        lock (_gate)
        {
            _processes = processes;
            _scanMicroseconds = cost;
        }

        _lastScan = now;
    }

    /// <summary>
    /// Local disks and their free space. Only the mounts from
    /// <see cref="ProcParser.ParseMounts"/> are asked: network filesystems aren't
    /// touched, because a hung NFS would hang the whole sampler.
    /// </summary>
    public async Task RefreshFilesystemsAsync(CancellationToken cancellationToken = default)
    {
        var mountinfo = await ReadTextAsync(Path.Combine(_root, "self/mountinfo"), cancellationToken);
        List<HostFilesystem> filesystems = [];

        foreach (var mount in ProcParser.ParseMounts(mountinfo ?? string.Empty).Take(MaxFilesystems))
        {
            try
            {
                var drive = new DriveInfo(mount.MountPoint);
                if (drive.IsReady && drive.TotalSize > 0)
                {
                    filesystems.Add(new HostFilesystem(mount.MountPoint, mount.Format, drive.TotalSize, drive.AvailableFreeSpace));
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                // Unmounted between listing and asking, hidden by ProtectHome, or a /proc copy from another box.
            }
        }

        lock (_gate)
        {
            _filesystems = filesystems;
        }
    }

    public void Dispose()
    {
        foreach (var handle in _handles.Values) handle.Dispose();
        _handles.Clear();
    }

    private static double Share(long part, long total) => total > 0 ? Math.Clamp((double)part / total, 0, 1) : 0;

    /// <summary>A counter going down (an interface that went away) isn't a negative rate: it's zero.</summary>
    private static double Rate(long current, long previous, double seconds) =>
        current >= previous ? (current - previous) / seconds : 0;

    /// <summary>A system file: opened once, re-read from the start.</summary>
    private async ValueTask<int> ReadSystemFileAsync(string name, CancellationToken cancellationToken)
    {
        if (!_handles.TryGetValue(name, out var handle))
        {
            var path = Path.Combine(_root, name);
            if (!File.Exists(path)) return 0;

            handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            _handles[name] = handle;
        }

        return await ReadFromStartAsync(handle, cancellationToken);
    }

    /// <summary>
    /// A process's <c>stat</c>: opened and closed, since there are hundreds and
    /// they come and go. A process exiting mid-read isn't an error.
    /// </summary>
    private async ValueTask<int> ReadOnceAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            using var handle = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return await ReadFromStartAsync(handle, cancellationToken);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return 0;
        }
    }

    private async ValueTask<int> ReadFromStartAsync(SafeFileHandle handle, CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < _buffer.Length)
        {
            var read = await RandomAccess.ReadAsync(handle, _buffer.AsMemory(total), total, cancellationToken);
            if (read == 0) break;
            total += read;
        }

        return total;
    }

    private async Task ReadIdentityAsync(CancellationToken cancellationToken)
    {
        var hostName = await FirstLineAsync(Path.Combine(_root, "sys/kernel/hostname"), cancellationToken);
        var kernel = await FirstLineAsync(Path.Combine(_root, "sys/kernel/osrelease"), cancellationToken);
        var cpuModel = await ValueAfterAsync(Path.Combine(_root, "cpuinfo"), "model name", ':', cancellationToken);
        var system = await ValueAfterAsync("/etc/os-release", "PRETTY_NAME", '=', cancellationToken);

        lock (_gate)
        {
            _hostName = hostName ?? Environment.MachineName;
            _kernel = kernel;
            _cpuModel = cpuModel;
            _operatingSystem = system?.Trim('"');
        }
    }

    private static async Task<string?> FirstLineAsync(string path, CancellationToken cancellationToken)
    {
        var text = await ReadTextAsync(path, cancellationToken);
        var line = text?.Split('\n', 2)[0].Trim();
        return string.IsNullOrEmpty(line) ? null : line;
    }

    private static async Task<string?> ValueAfterAsync(string path, string key, char separator, CancellationToken cancellationToken)
    {
        var text = await ReadTextAsync(path, cancellationToken);
        if (text is null) return null;

        foreach (var line in text.Split('\n'))
        {
            var at = line.IndexOf(separator, StringComparison.Ordinal);
            if (at > 0 && line[..at].Trim().Equals(key, StringComparison.Ordinal))
            {
                var value = line[(at + 1)..].Trim();
                return value.Length > 0 ? value : null;
            }
        }

        return null;
    }

    private static async Task<string?> ReadTextAsync(string path, CancellationToken cancellationToken)
    {
        try
        {
            return File.Exists(path) ? await File.ReadAllTextAsync(path, cancellationToken) : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private readonly record struct ProcessEntry(string Name, long Ticks);
}
