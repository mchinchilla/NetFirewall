using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using NetFirewall.Services.Monitoring.Host;
using NetFirewall.Web.Models.Monitoring;

namespace NetFirewall.Tests.Monitoring;

/// <summary>
/// The host monitor reads /proc the way the kernel writes it. The texts here are
/// trimmed from a real Debian 13: what's checked is that it counts what should be
/// counted — whole disks, not their partitions; physical NICs, not loopback,
/// container bridges, IFB or tunnels (each re-counts bytes a NIC already saw).
/// </summary>
public sealed class ProcParserTests
{
    internal const string Stat = """
        cpu  1000 50 300 8000 100 20 30 0 0 0
        cpu0 500 25 150 4000 50 10 15 0 0 0
        cpu1 500 25 150 4000 50 10 15 0 0 0
        intr 123456 0 0
        ctxt 987654
        btime 1760000000
        """;

    internal const string MemInfo = """
        MemTotal:       16384000 kB
        MemFree:         2000000 kB
        MemAvailable:   12288000 kB
        Buffers:          100000 kB
        Cached:          3000000 kB
        SwapCached:            0 kB
        SwapTotal:       1024000 kB
        SwapFree:         768000 kB
        SReclaimable:     200000 kB
        """;

    internal const string DiskStats = """
           7       0 loop0 10 0 800 0 0 0 0 0 0 0 0 0 0 0 0 0 0
           8       0 sda 1000 0 20000 0 500 0 10000 0 0 0 0 0 0 0 0 0 0
           8       1 sda1 900 0 18000 0 450 0 9000 0 0 0 0 0 0 0 0 0 0
         259       0 nvme0n1 100 0 2000 0 50 0 1000 0 0 0 0 0 0 0 0 0 0
         259       1 nvme0n1p1 90 0 1800 0 40 0 800 0 0 0 0 0 0 0 0 0 0
         254       0 vda 10 0 400 0 5 0 200 0 0 0 0 0 0 0 0 0 0
         253       0 dm-0 999 0 99999 0 999 0 99999 0 0 0 0 0 0 0 0 0 0
        """;

    internal const string NetDev = """
        Inter-|   Receive                                                |  Transmit
         face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
            lo: 9999999    100    0    0    0     0          0         0  9999999     100    0    0    0     0       0          0
        ens192: 5000000   4000    0    0    0     0          0         0  2000000    3000    0    0    0     0       0          0
        ens256:  100000    400    0    0    0     0          0         0    50000     300    0    0    0     0       0          0
           wg0:  444444     10    0    0    0     0          0         0   444444      10    0    0    0     0       0          0
          ifb0:  333333     10    0    0    0     0          0         0   333333      10    0    0    0     0       0          0
        docker0: 777777    10    0    0    0     0          0         0   777777      10    0    0    0     0       0          0
        veth12ab: 888888   10    0    0    0     0          0         0   888888      10    0    0    0     0       0          0
        br-5f1e2d: 66666   10    0    0    0     0          0         0    66666      10    0    0    0     0       0          0
        """;

    private static byte[] U(string text) => Encoding.UTF8.GetBytes(text);

    [Fact]
    public void Cpu_SplitsUserSystemAndIoWait_AndCountsCores()
    {
        Assert.True(ProcParser.TryParseCpu(U(Stat), out var cpu, out var cores));

        Assert.Equal(2, cores);
        Assert.Equal(1050, cpu.User);     // user includes nice
        Assert.Equal(350, cpu.System);    // system includes irq + softirq
        Assert.Equal(100, cpu.IoWait);
        Assert.Equal(9500, cpu.Total);    // guest is already inside user, not added twice
    }

    [Fact]
    public void MemoryUsed_IsTotalMinusAvailable()
    {
        Assert.True(ProcParser.TryParseMemory(U(MemInfo), out var memory));

        Assert.Equal(16384000L * 1024, memory.Total);
        Assert.Equal((16384000L - 12288000L) * 1024, memory.Used);
        Assert.Equal((100000L + 3000000L + 200000L) * 1024, memory.Cache);
        Assert.Equal(1024000L * 1024, memory.SwapTotal);
        Assert.Equal(256000L * 1024, memory.SwapUsed);
    }

    [Fact]
    public void Disk_CountsWholeDisks_NotPartitionsOrLvm()
    {
        // sda + sda1 would count the same bytes twice; dm-0 is LVM on top of sda.
        Assert.True(ProcParser.TryParseDisks(U(DiskStats), out var read, out var written));

        Assert.Equal((20000L + 2000 + 400) * 512, read);
        Assert.Equal((10000L + 1000 + 200) * 512, written);
    }

    [Theory]
    [InlineData("sda", true)]
    [InlineData("sdab", true)]
    [InlineData("sda1", false)]
    [InlineData("vdb", true)]
    [InlineData("xvda", true)]
    [InlineData("xvda2", false)]
    [InlineData("nvme0n1", true)]
    [InlineData("nvme0n1p2", false)]
    [InlineData("mmcblk0", true)]
    [InlineData("mmcblk0p1", false)]
    [InlineData("loop3", false)]
    [InlineData("dm-1", false)]
    [InlineData("md0", false)]
    [InlineData("sr0", false)]
    public void WholeDisk_IsRecognisedByName(string name, bool whole) =>
        Assert.Equal(whole, ProcParser.IsWholeDisk(U(name)));

    [Fact]
    public void Network_AddsPhysicalNics_SkippingLoopbackBridgesIfbAndTunnels()
    {
        Assert.True(ProcParser.TryParseNetwork(U(NetDev), out var received, out var sent));

        Assert.Equal(5100000, received);
        Assert.Equal(2050000, sent);
    }

    [Fact]
    public void Mounts_AreOnePerDevice_WithoutSystemdBindsOrNonDisks()
    {
        // What the Web sees inside its unit: ReadWritePaths and PrivateTmp mount
        // the same disk again — they aren't separate disks.
        const string mountinfo = """
            22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw,errors=remount-ro
            23 22 0:21 / /proc rw,nosuid shared:2 - proc proc rw
            30 22 8:1 /var/lib/netfirewall/web /var/lib/netfirewall/web rw,relatime shared:1 - ext4 /dev/sda1 rw
            31 22 8:1 /tmp/systemd-private-abc/tmp /tmp rw,relatime - ext4 /dev/sda1 rw
            32 22 8:15 / /boot/efi rw,relatime shared:3 - vfat /dev/sda15 rw
            33 22 0:30 / /run rw - tmpfs tmpfs rw
            34 22 8:17 / /var/lib/postgresql rw,relatime - xfs /dev/sdb1 rw
            35 22 8:17 / /srv/other\040copy rw,relatime - xfs /dev/sdb1 rw
            36 22 0:45 / /mnt/nas rw - nfs4 nas:/export rw
            """;

        var mounts = ProcParser.ParseMounts(mountinfo).Select(m => (m.MountPoint, m.Format)).ToArray();

        Assert.Equal([("/", "ext4"), ("/boot/efi", "vfat"), ("/var/lib/postgresql", "xfs")], mounts);
    }

    [Fact]
    public void MountPointWithSpaces_IsUnescaped() =>
        Assert.Equal("/media/my disk",
            ProcParser.ParseMounts("40 22 8:33 / /media/my\\040disk rw - ext4 /dev/sdc1 rw\n").Single().MountPoint);

    [Fact]
    public void Load_IsTheThreeAverages()
    {
        Assert.True(ProcParser.TryParseLoad(U("0.42 1.50 12.07 2/345 6789\n"), out var one, out var five, out var fifteen));

        Assert.Equal((0.42, 1.50, 12.07), (one, five, fifteen));
    }

    [Fact]
    public void Process_ParsesEvenWhenNameHoldsSpacesAndParentheses()
    {
        // Fields are counted from the last ')'.
        const string line = "4242 (Web (Content)) S 1 4242 4242 0 -1 4194560 100 0 0 0 1500 250 0 0 20 0 9 0 300 999999 2560 18446744073709551615";

        Assert.True(ProcParser.TryParseProcess(U(line), out var name, out var ticks, out var pages, out var kernel));

        Assert.Equal("Web (Content)", Encoding.UTF8.GetString(name));
        Assert.Equal(1750, ticks);
        Assert.Equal(2560, pages);
        Assert.False(kernel);
    }
}

/// <summary>The sampler over a fake /proc directory.</summary>
public sealed class HostMetricsSamplerTests : IDisposable
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 27, 12, 0, 0, TimeSpan.Zero);

    private readonly string _proc = Directory.CreateTempSubdirectory("netfw-proc-").FullName;

    public void Dispose() => Directory.Delete(_proc, recursive: true);

    private HostMetricsSampler Sampler(string? root = null) => new(
        Options.Create(new HostMonitorOptions { ProcRoot = root ?? _proc }),
        TimeProvider.System,
        NullLogger<HostMetricsSampler>.Instance);

    [Fact]
    public async Task Sample_ComputesRatesAndSharesBetweenTwoReads()
    {
        Write("stat", ProcParserTests.Stat);
        Write("meminfo", ProcParserTests.MemInfo);
        Write("diskstats", ProcParserTests.DiskStats);
        Write("net/dev", ProcParserTests.NetDev);
        Write("loadavg", "0.42 1.50 12.07 2/345 6789\n");
        Write("uptime", "1123200.50 2000000.00\n");

        using var sampler = Sampler();
        Assert.True(await sampler.SampleAsync(T0));

        // One second later: 200 of 1900 CPU ticks busy, 1 MB read, 100 KB received.
        Write("stat", ProcParserTests.Stat.Replace("cpu  1000 50 300 8000 100", "cpu  1100 50 400 9700 100", StringComparison.Ordinal));
        Write("diskstats", ProcParserTests.DiskStats.Replace("sda 1000 0 20000", "sda 1000 0 22048", StringComparison.Ordinal));
        Write("net/dev", ProcParserTests.NetDev.Replace("ens192: 5000000", "ens192: 5102400", StringComparison.Ordinal));
        Assert.True(await sampler.SampleAsync(T0.AddSeconds(1)));

        var state = sampler.Snapshot(T0.AddMinutes(-1))!;

        Assert.Equal(2, state.Identity.Cores);
        Assert.Equal(16384000L * 1024, state.Identity.MemoryTotal);
        Assert.Equal(T0.AddSeconds(1).AddSeconds(-1123200.50), state.Identity.BootedOn);
        var sample = Assert.Single(state.Samples); // the first read only sets the baseline

        Assert.Equal(100.0 / 1900, sample.CpuUser, 9);
        Assert.Equal(100.0 / 1900, sample.CpuSystem, 9);
        Assert.Equal(2048 * 512, sample.DiskReadBytesPerSecond);
        Assert.Equal(102400, sample.NetworkInBytesPerSecond);
        Assert.Equal(0.42, sample.Load1);
        Assert.Equal((16384000L - 12288000L) * 1024, sample.MemoryUsed);
    }

    [Fact]
    public async Task Processes_GroupByName_AndCpuIsWhatTheySpentBetweenWalks()
    {
        Write("stat", ProcParserTests.Stat);
        Write("uptime", "100.0 100.0\n");
        Write("4242/stat", "4242 (nginx) S 1 4242 4242 0 -1 0 0 0 0 0 100 50 0 0 20 0 9 0 300 999 1000 0");
        Write("4243/stat", "4243 (nginx) S 1 4243 4243 0 -1 0 0 0 0 0 200 50 0 0 20 0 9 0 300 999 500 0");
        Write("5000/stat", "5000 (postgres) S 1 5000 5000 0 -1 0 0 0 0 0 10 0 0 0 20 0 9 0 300 999 300 0");
        Write("6000/stat", "6000 (kworker/0:1-events) I 2 0 0 0 -1 2129984 0 0 0 0 5 5 0 0 20 0 1 0 10 0 0 0");
        Write("6001/stat", "6001 (ksoftirqd/0) S 2 0 0 0 -1 2129984 0 0 0 0 7 3 0 0 20 0 1 0 10 0 0 0");

        using var sampler = Sampler();
        await sampler.SampleAsync(T0);
        await sampler.ScanProcessesAsync(T0);

        // Five seconds and 100 more ticks on one worker: 100 / (100 ticks/s * 5 s * 2 cores) = 10 %.
        Write("4242/stat", "4242 (nginx) S 1 4242 4242 0 -1 0 0 0 0 0 200 50 0 0 20 0 9 0 300 999 1000 0");
        await sampler.ScanProcessesAsync(T0.AddSeconds(5));

        var processes = sampler.Snapshot(T0)!.Processes;
        var nginx = processes.Single(p => p.Name == "nginx");
        Assert.Equal(2, nginx.Instances);
        Assert.Equal(0.10, nginx.CpuShare, 9);
        Assert.Equal(1500L * Environment.SystemPageSize, nginx.ResidentBytes);
        Assert.Equal(0, processes.Single(p => p.Name == "postgres").CpuShare);
        // Each kernel thread has its own name and would flood the list: they share one row.
        Assert.Equal(2, processes.Single(p => p.Name == HostProcessGroup.KernelThreads).Instances);
    }

    [Fact]
    public void WithoutProc_ThereIsNoMonitor()
    {
        using var sampler = Sampler(Path.Combine(_proc, "missing"));

        Assert.Null(sampler.Snapshot(DateTimeOffset.MinValue));
    }

    private void Write(string path, string content)
    {
        var file = Path.Combine(_proc, path);
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllText(file, content.Replace("\r\n", "\n", StringComparison.Ordinal));
    }
}

/// <summary>
/// Samples bucketed into the dot-matrix columns. Each column averages what lands
/// in it; an empty column stays empty, except a lone gap between two full ones,
/// which is the timer and not the host.
/// </summary>
public sealed class HostTimelineTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 27, 12, 0, 0, TimeSpan.Zero);

    private static readonly HostIdentity Box =
        new("fw", "Debian GNU/Linux 13 (trixie)", "6.12.0", "Xeon", 8, 8L << 30, 0, Now.AddDays(-20));

    internal static HostSample Sample(DateTimeOffset at, double cpu = 0.5, double netIn = 0) =>
        new(at, cpu, 0.1, 0, 4L << 30, 1L << 30, 0, 1.5, 1.2, 1.0, 0, 0, netIn, 0);

    private static HostMonitorState State(IReadOnlyList<HostSample> samples, IReadOnlyList<HostProcessGroup>? processes = null) =>
        new(Box, samples, processes ?? [], [new HostFilesystem("/", "ext4", 100, 40)], new HostMonitorCost(1, 5, 80, 2000, 30L << 20));

    [Fact]
    public void Column_AveragesTheSamplesInIt()
    {
        // Six ten-second columns ending now: the last is (now-10, now].
        var columns = HostTimeline.Columns([Sample(Now.AddSeconds(-9), cpu: 0.2), Sample(Now, cpu: 0.4)], Now, TimeSpan.FromSeconds(60), 6);

        Assert.Equal(6, columns.Count);
        Assert.Equal(0.3, columns[5]!.Value.CpuUser, 9);
        Assert.All(columns.Take(5), c => Assert.Null(c));
    }

    [Fact]
    public void Rates_AreAveragedToo_AndTimeIsTheLastSample()
    {
        var columns = HostTimeline.Columns(
            [Sample(Now.AddSeconds(-8), netIn: 1000), Sample(Now.AddSeconds(-1), netIn: 3000)], Now, TimeSpan.FromSeconds(60), 6);

        Assert.Equal(2000, columns[5]!.Value.NetworkInBytesPerSecond);
        Assert.Equal(4L << 30, columns[5]!.Value.MemoryUsed);
        Assert.Equal(Now.AddSeconds(-1), columns[5]!.Value.Time);
    }

    [Fact]
    public void OutsideTheWindow_DoesNotCount()
    {
        var columns = HostTimeline.Columns(
            [Sample(Now.AddSeconds(-60)), Sample(Now.AddSeconds(-90)), Sample(Now.AddSeconds(5))], Now, TimeSpan.FromSeconds(60), 6);

        Assert.All(columns, c => Assert.Null(c));
    }

    [Fact]
    public void LoneGapBetweenFullColumns_TakesThePreviousOne()
    {
        // One sample a second, one column a second: with the timer half a second
        // off, two samples land in one column and the next is empty. Painting it
        // empty would make the matrix flicker on every refresh.
        var columns = HostTimeline.Columns(
            [
                Sample(Now.AddSeconds(-3.9), cpu: 0.1), Sample(Now.AddSeconds(-3.1), cpu: 0.3),
                Sample(Now.AddSeconds(-1.5), cpu: 0.5), Sample(Now, cpu: 0.6),
            ],
            Now, TimeSpan.FromSeconds(6), 6);

        Assert.Equal(0.2, columns[2]!.Value.CpuUser, 9);
        Assert.Equal(0.2, columns[3]!.Value.CpuUser, 9);
        Assert.Equal(0.5, columns[4]!.Value.CpuUser);
        Assert.Equal(0.6, columns[5]!.Value.CpuUser);
        Assert.Null(columns[0]); // nothing to repeat before the first sample
        Assert.Null(columns[1]);
    }

    [Fact]
    public void TwoEmptyColumnsInARow_AreARealGap()
    {
        // The Web was down, or the sampler couldn't read: that shows, it isn't papered over.
        var columns = HostTimeline.Columns([Sample(Now.AddSeconds(-5.5)), Sample(Now.AddSeconds(-2.5))], Now, TimeSpan.FromSeconds(6), 6);

        Assert.NotNull(columns[0]);
        Assert.Null(columns[1]);
        Assert.Null(columns[2]);
        Assert.NotNull(columns[3]);
    }

    [Theory]
    [InlineData(null, 60)]
    [InlineData(60, 60)]
    [InlineData(300, 300)]
    [InlineData(900, 900)]
    [InlineData(3600, 3600)]
    [InlineData(42, 60)]
    [InlineData(-1, 60)]
    public void Window_OnlyAcceptsTheSelectorValues(int? requested, int expected) =>
        Assert.Equal(expected, HostWindows.Clean(requested));

    private static Task<NetFirewall.Models.ServiceResponse<HostMonitorView>> QueryAsync(Mock<IHostMonitor> monitor, int window = 60) =>
        new HostMonitorQueryService(monitor.Object, new FixedTime(Now)).GetAsync(window);

    [Fact]
    public async Task WithoutProc_SaysSoInsteadOfPaintingZeros()
    {
        var monitor = new Mock<IHostMonitor>();
        monitor.Setup(m => m.Snapshot(It.IsAny<DateTimeOffset>())).Returns((HostMonitorState?)null);

        var result = await QueryAsync(monitor);

        Assert.False(result.Success);
        Assert.False(string.IsNullOrEmpty(result.Message));
    }

    [Fact]
    public async Task Matrix_EndsAtTheLastSample_NotTheClock()
    {
        // The last sample is 0.7 s old: if the window ended at the clock, the
        // current second's column would come out empty on every refresh.
        var last = Now.AddSeconds(-0.7);
        var monitor = new Mock<IHostMonitor>();
        monitor.Setup(m => m.Snapshot(Now.AddSeconds(-HostWindows.Default - 1)))
               .Returns(State([Sample(last.AddSeconds(-1), cpu: 0.1), Sample(last, cpu: 0.9)]));

        var view = (await QueryAsync(monitor)).Data!;

        Assert.Equal(0.9, view.Current!.Value.CpuUser);
        Assert.Equal(HostTimeline.WideColumns, view.Wide.Count);
        Assert.Equal(HostTimeline.NarrowColumns, view.Narrow.Count);
        Assert.Equal(0.9, view.Wide[^1]!.Value.CpuUser);
        Assert.Equal(0.1, view.Wide[^2]!.Value.CpuUser);
        Assert.Equal(Box, view.Identity);
        Assert.Equal(60, view.WindowSeconds);
    }

    [Fact]
    public async Task UnknownWindow_FallsBackToOneMinute()
    {
        var monitor = new Mock<IHostMonitor>();
        monitor.Setup(m => m.Snapshot(It.IsAny<DateTimeOffset>())).Returns(State([]));

        var view = (await QueryAsync(monitor, window: 123456)).Data!;

        Assert.Equal(60, view.WindowSeconds);
        Assert.Null(view.Current);
        Assert.All(view.Wide, c => Assert.Null(c));
    }

    [Fact]
    public async Task Processes_SortBusiestFirst_AndOnlyTheTop()
    {
        HostProcessGroup[] processes = [.. Enumerable.Range(1, 12).Select(n => new HostProcessGroup($"p{n}", 1, n / 100.0, n * 1000))];
        var monitor = new Mock<IHostMonitor>();
        monitor.Setup(m => m.Snapshot(It.IsAny<DateTimeOffset>())).Returns(State([Sample(Now)], processes));

        var view = (await QueryAsync(monitor)).Data!;

        Assert.Equal(["p12", "p11", "p10", "p9", "p8", "p7", "p6", "p5"], view.Processes.Select(p => p.Name));
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}

/// <summary>How a column of the dot matrix splits between stacked series.</summary>
public sealed class DotMatrixSvgTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 27, 12, 0, 0, TimeSpan.Zero);

    private static readonly DotLayer[] Cpu =
    [
        new(s => s.CpuSystem, "--metric-cpu-system"),
        new(s => s.CpuUser, "--metric-cpu-user"),
    ];

    [Fact]
    public void Column_FillsToTheValue_SplitBetweenSeries()
    {
        // 25% system + 25% user of a 0..1 scale = 4 of 8 rows, two each.
        var sample = HostTimelineTests.Sample(Now, cpu: 0.25) with { CpuSystem = 0.25 };

        var segments = DotMatrixSvg.Segments(sample, Cpu, 1).ToArray();

        Assert.Equal([(0, 2, "--metric-cpu-system"), (2, 4, "--metric-cpu-user")], segments);
    }

    [Fact]
    public void AnythingAboveZero_ShowsAtLeastOneDot_AndOverflowStaysOnTop()
    {
        var tiny = HostTimelineTests.Sample(Now, cpu: 0.001) with { CpuSystem = 0 };
        var huge = HostTimelineTests.Sample(Now, cpu: 5) with { CpuSystem = 0 };

        Assert.Equal([(0, 1, "--metric-cpu-user")], DotMatrixSvg.Segments(tiny, Cpu, 1));
        Assert.Equal([(0, DotMatrixSvg.Rows, "--metric-cpu-user")], DotMatrixSvg.Segments(huge, Cpu, 1));
    }

    [Fact]
    public void Render_UsesThemeTokens_NeverRawColours()
    {
        var columns = new HostSample?[] { null, HostTimelineTests.Sample(Now) };

        var html = DotMatrixSvg.Render("t", columns, Cpu, 1, "CPU <x>").ToString()!;

        Assert.Contains("fill:var(--metric-dot-empty)", html);
        Assert.Contains("fill:var(--metric-cpu-user)", html);
        Assert.DoesNotContain("#", html.Replace("url(#", "", StringComparison.Ordinal));
        Assert.Contains("aria-label=\"CPU &lt;x&gt;\"", html);
    }
}
