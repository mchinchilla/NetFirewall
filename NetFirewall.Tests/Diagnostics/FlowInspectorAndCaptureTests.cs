using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Diagnostics;
using NetFirewall.Services.Diagnostics.Capture;
using NetFirewall.Services.Diagnostics.Jobs;
using NetFirewall.Services.Diagnostics.Trace;
using NetFirewall.Services.Processes;

namespace NetFirewall.Tests.Diagnostics;

/// <summary>Pure logic of the two invasive tools, plus the cleanup guarantee the tracer owes the kernel.</summary>
public class FlowInspectorAndCaptureTests
{
    // ───────────────────────── nft trace parsing ─────────────────────────

    [Fact]
    public void Trace_ParsesEveryLineKind_AndGroupsByPacket()
    {
        string[] lines =
        [
            "trace id 4e0e1e5b ip filter input packet: iif \"ens192\" ip saddr 1.2.3.4 ip daddr 5.6.7.8 ip protocol tcp tcp dport 22",
            "trace id 4e0e1e5b ip filter input rule ip saddr 1.2.3.4 tcp dport 22 drop (verdict drop)",
            "trace id 4e0e1e5b ip filter input verdict drop",
        ];

        var events = lines.Select(FlowInspectorService.ParseLine).OfType<TraceEvent>().ToList();

        Assert.Equal(3, events.Count);
        Assert.All(events, e => Assert.Equal("4e0e1e5b", e.TraceId));
        Assert.Equal(["packet", "rule", "verdict"], events.Select(e => e.Kind));
        Assert.Equal("filter", events[0].Table);
        Assert.Equal("input", events[0].Chain);
        Assert.Contains("tcp dport 22", events[1].Detail);

        var result = new TraceResult(events, "ip saddr 1.2.3.4", false, 0);
        Assert.Equal(1, result.PacketCount);
    }

    [Theory]
    [InlineData("")]
    [InlineData("some unrelated nft output")]
    [InlineData("trace id 123 ip filter input somethingelse")]
    public void Trace_IgnoresNonTraceLines(string line) =>
        Assert.Null(FlowInspectorService.ParseLine(line));

    // ───────────────────────── matcher construction ─────────────────────────

    [Fact]
    public void Trace_Matchers_AreArgumentVectors_AndOutputChainHasNoIif()
    {
        var (pre, outMatch, spec) = FlowInspectorService.BuildMatchers(
            new TraceRequest(Src: "192.168.99.60", Dst: "1.1.1.1", Protocol: "tcp", Port: 443, Interface: "ens256"));

        // Every token is its own argv element — nothing is concatenated.
        Assert.Equal(["iifname", "ens256", "ip", "saddr", "192.168.99.60", "ip", "daddr", "1.1.1.1", "ip", "protocol", "tcp", "tcp", "dport", "443"], pre);
        // Locally generated packets have no ingress interface; nft would reject iifname there.
        Assert.DoesNotContain("iifname", outMatch);
        Assert.Contains("192.168.99.60", spec);
    }

    [Fact]
    public void Trace_PortIsIgnoredWithoutATransportProtocol()
    {
        var (pre, _, _) = FlowInspectorService.BuildMatchers(new TraceRequest(Src: "10.0.0.1", Port: 443));
        Assert.DoesNotContain("dport", pre);
    }

    // ───────────────────────── cleanup guarantee ─────────────────────────

    [Fact]
    public async Task Trace_DeletesItsTable_EvenWhenTheMonitorNeverStarts()
    {
        var runner = new Mock<IProcessRunner>();
        var nftCalls = new List<string>();
        runner.Setup(r => r.RunAsync(It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
              .Callback<string, IReadOnlyList<string>, TimeSpan?, CancellationToken>((_, args, _, _) => nftCalls.Add(string.Join(' ', args)))
              .ReturnsAsync(new ProcessResult(0, "", ""));
        // The streaming monitor blows up — the table must still go away.
        runner.Setup(r => r.Start(It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CancellationToken>()))
              .Throws(new InvalidOperationException("nft monitor unavailable"));

        var registry = new DiagnosticJobRegistry(NullLogger<DiagnosticJobRegistry>.Instance);
        var svc = new FlowInspectorService(runner.Object, registry, Options.Create(new DiagnosticsOptions()), NullLogger<FlowInspectorService>.Instance);

        var id = svc.Start(new TraceRequest(Src: "10.0.0.1", DurationSec: 5), "marvin");
        Assert.NotNull(id);

        var snap = await WaitForFinishAsync(registry, id.Value);
        Assert.NotEqual(DiagJobState.Running, snap.State);

        if (OperatingSystem.IsLinux())
        {
            Assert.Contains(nftCalls, c => c.StartsWith("add table ip netfw_diag", StringComparison.Ordinal));
            Assert.Contains(nftCalls, c => c == "delete table ip netfw_diag");
        }
        else
        {
            // Off Linux the tool refuses up front and never touches nft.
            Assert.Equal(DiagJobState.Completed, snap.State);
            Assert.Contains("Linux-only", snap.Trace!.Error);
        }
    }

    [Fact]
    public async Task Trace_ReleasesTheSlotWhenItEnds()
    {
        var runner = new Mock<IProcessRunner>();
        runner.Setup(r => r.RunAsync(It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
              .ReturnsAsync(new ProcessResult(0, "", ""));
        runner.Setup(r => r.Start(It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<CancellationToken>()))
              .Throws(new InvalidOperationException("boom"));

        var registry = new DiagnosticJobRegistry(NullLogger<DiagnosticJobRegistry>.Instance);
        var svc = new FlowInspectorService(runner.Object, registry, Options.Create(new DiagnosticsOptions()), NullLogger<FlowInspectorService>.Instance);

        var id = svc.Start(new TraceRequest(Src: "10.0.0.1"), null)!;
        await WaitForFinishAsync(registry, id.Value);

        Assert.Null(registry.Current);
        Assert.NotNull(registry.TryStart(DiagJobKind.Capture, "ens192", null));
    }

    // ───────────────────────── capture ─────────────────────────

    [Theory]
    [InlineData("12 packets captured\n12 packets received by filter\n0 packets dropped by kernel\n", 12)]
    [InlineData("1 packet captured\n", 1)]
    [InlineData("tcpdump: listening on ens192\n", null)]
    public void Capture_ParsesTcpdumpCounters(string stderr, int? expected) =>
        Assert.Equal(expected, PacketCaptureService.ParseCapturedCount(stderr));

    [Fact]
    public void CaptureStore_KeysFilesByJobId_AndPurgesByAge()
    {
        var dir = Path.Combine(Path.GetTempPath(), "nf-capture-tests-" + Guid.NewGuid().ToString("N")[..8]);
        try
        {
            var store = new CaptureStore(Options.Create(new DiagnosticsOptions { CaptureDirectory = dir }), NullLogger<CaptureStore>.Instance);
            var id = Guid.NewGuid();

            var path = store.PathFor(id);
            Assert.StartsWith(dir, path);
            Assert.EndsWith(".pcap", path);
            Assert.DoesNotContain("..", path);

            File.WriteAllText(path, "pcap");
            using (var s = store.OpenRead(id)) Assert.NotNull(s);
            Assert.Equal(4, store.TotalBytes());

            Assert.Equal(0, store.PurgeOlderThan(TimeSpan.FromHours(1)));   // fresh → kept
            File.SetLastWriteTimeUtc(path, DateTime.UtcNow.AddHours(-2));
            Assert.Equal(1, store.PurgeOlderThan(TimeSpan.FromHours(1)));
            Assert.Null(store.OpenRead(id));
        }
        finally
        {
            try { Directory.Delete(dir, recursive: true); } catch { /* best effort */ }
        }
    }

    // ───────────────────────── BPF filter allow-list ─────────────────────────

    [Theory]
    [InlineData("host 192.168.99.60 and port 443", true)]
    [InlineData("tcp port 22 or (udp and portrange 10000-20000)", true)]
    [InlineData("ip[0] & 0xf != 5", true)]
    [InlineData("", true)]
    [InlineData("host 1.2.3.4; rm -rf /", false)]
    [InlineData("host $(id)", false)]
    [InlineData("-w /etc/shadow", false)]
    [InlineData("host `id`", false)]
    public void BpfFilter_AllowsPcapSyntaxOnly(string filter, bool ok)
    {
        var v = new DiagnosticInputValidator();
        Assert.Equal(ok, v.TryBpfFilter(filter, out _, out _));
    }

    private static async Task<DiagJobSnapshot> WaitForFinishAsync(IDiagnosticJobRegistry reg, Guid id)
    {
        for (var i = 0; i < 100; i++)
        {
            var snap = reg.Get(id);
            if (snap is { IsRunning: false }) return snap;
            await Task.Delay(20);
        }
        throw new TimeoutException("The job never finished.");
    }
}
