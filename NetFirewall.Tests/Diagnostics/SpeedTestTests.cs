using System.Net;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Diagnostics;
using NetFirewall.Services.Diagnostics.Jobs;
using NetFirewall.Services.Diagnostics.SpeedTest;

namespace NetFirewall.Tests.Diagnostics;

/// <summary>
/// WAN speed test: the measurement loop against a fake server, the kept-file
/// lifecycle (24 h expiry, orphans, quota), and the URL guard that keeps the
/// daemon from fetching anything but a public test server.
/// </summary>
public sealed class SpeedTestTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "nf-speedtest-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        try { Directory.Delete(_dir, recursive: true); } catch { /* best effort */ }
    }

    private DiagnosticsOptions Opts(int quotaMb = 4096) => new()
    {
        SpeedTestDirectory = _dir,
        SpeedTestRetentionHours = 24,
        SpeedTestQuotaMegabytes = quotaMb,
        SpeedTestFreeSpaceReserveMegabytes = 0,
    };

    private SpeedTestStore Store(int quotaMb = 4096) => new(Options.Create(Opts(quotaMb)), NullLogger<SpeedTestStore>.Instance);

    private static SpeedTestFile Meta(Guid id, DateTime created, TimeSpan life) =>
        new(id, "speedtest-ens192.bin", 3, true, "ens192", "Fake", 100, created, created + life, "marvin");

    // ───────────────────────── measurement ─────────────────────────

    private sealed class Harness
    {
        public required SpeedTestService Service { get; init; }
        public required DiagnosticJobRegistry Jobs { get; init; }
        public required Mock<IDiagnosticRunStore> Runs { get; init; }
    }

    private Harness NewService(HttpMessageHandler server, ISpeedTestStore store)
    {
        var clients = new Mock<IMarkedHttpClientFactory>();
        clients.Setup(c => c.Create(It.IsAny<long>())).Returns(() => new HttpClient(server, disposeHandler: false));

        var ifaces = new Mock<IInterfaceHealthService>();
        ifaces.Setup(i => i.GetAsync(It.IsAny<string>(), It.IsAny<CancellationToken>())).ReturnsAsync((InterfaceHealth?)null);

        var runs = new Mock<IDiagnosticRunStore>();
        runs.Setup(r => r.StartAsync(It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<object?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Guid.NewGuid());
        var sp = new ServiceCollection().AddScoped(_ => runs.Object).BuildServiceProvider();

        var jobs = new DiagnosticJobRegistry(NullLogger<DiagnosticJobRegistry>.Instance);
        var service = new SpeedTestService(jobs, clients.Object, store, ifaces.Object,
            sp.GetRequiredService<IServiceScopeFactory>(), Options.Create(Opts()), NullLogger<SpeedTestService>.Instance);
        return new Harness { Service = service, Jobs = jobs, Runs = runs };
    }

    private static async Task<DiagJobSnapshot> WaitAsync(DiagnosticJobRegistry jobs, Guid id)
    {
        for (var i = 0; i < 200; i++)
        {
            if (jobs.Get(id) is { IsRunning: false } done) return done;
            await Task.Delay(50);
        }
        throw new TimeoutException("speed test job never finished");
    }

    private static SpeedTestPlan Plan(long capBytes, bool keep, int streams = 2, int seconds = 10) =>
        new("ens192", 0x100, "Fake", new Uri("https://speed.example.com/1GB.bin"), seconds, capBytes, streams, keep);

    /// <summary>Serves <paramref name="size"/> bytes per request, or a fixed status.</summary>
    private sealed class FakeServer(int size, HttpStatusCode status = HttpStatusCode.OK) : HttpMessageHandler
    {
        public int Requests;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref Requests);
            var resp = new HttpResponseMessage(status);
            if (status == HttpStatusCode.OK)
            {
                var body = new byte[size];
                for (var i = 0; i < size; i++) body[i] = (byte)(i % 251);
                resp.Content = new ByteArrayContent(body);
            }
            return Task.FromResult(resp);
        }
    }

    [Fact]
    public async Task StopsAtTheByteCap_RequestsAgainUntilThen_AndKeepsTheFirstFullResponse()
    {
        var server = new FakeServer(size: 256 * 1024);
        var h = NewService(server, Store());

        var id = h.Service.Start(Plan(capBytes: 2_000_000, keep: true), "marvin")!.Value;
        var job = await WaitAsync(h.Jobs, id);

        Assert.Equal(DiagJobState.Completed, job.State);
        var r = job.SpeedTest!;
        Assert.True(r.Bytes >= 2_000_000, $"got {r.Bytes}");
        Assert.True(r.ReachedByteCap);
        // A 256 KB file cannot satisfy a 2 MB cap: the connections must have re-requested it.
        Assert.True(server.Requests > 2);
        Assert.Null(r.Error);
        Assert.Equal(0x100, r.Fwmark);

        // The kept file is exactly one response — a faithful copy — not every stream's bytes.
        var file = Assert.IsType<SpeedTestFile>(r.File);
        Assert.Equal(256 * 1024, file.SizeBytes);
        Assert.True(file.Complete);
        Assert.Equal(TimeSpan.FromHours(24), file.ExpiresAtUtc - file.CreatedAtUtc);
        var opened = await Store().OpenReadAsync(file.Id);
        Assert.NotNull(opened);
        await using (opened.Value.Content)
        {
            var copy = new MemoryStream();
            await opened.Value.Content.CopyToAsync(copy);
            Assert.Equal((byte)(1000 % 251), copy.ToArray()[1000]);
        }

        h.Runs.Verify(x => x.FinishAsync(It.IsAny<Guid>(), DiagRunStatus.Ok, It.IsAny<object?>(), It.Is<string?>(s => s!.Contains("ens192")), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task WithoutKeepFile_NothingTouchesTheDisk()
    {
        var h = NewService(new FakeServer(size: 64 * 1024), Store());

        var id = h.Service.Start(Plan(capBytes: 500_000, keep: false), null)!.Value;
        var job = await WaitAsync(h.Jobs, id);

        Assert.Null(job.SpeedTest!.File);
        Assert.False(Directory.Exists(_dir) && Directory.EnumerateFiles(_dir).Any());
    }

    [Fact]
    public async Task ServerError_FailsTheJob_WithTheStatus_AndLeavesNoFile()
    {
        var h = NewService(new FakeServer(0, HttpStatusCode.NotFound), Store());

        var id = h.Service.Start(Plan(capBytes: 1_000_000, keep: true), null)!.Value;
        var job = await WaitAsync(h.Jobs, id);

        Assert.Equal(DiagJobState.Failed, job.State);
        Assert.Contains("404", job.Message);
        Assert.Equal(0, job.SpeedTest!.Bytes);   // the result is kept so the panel can name the source
        Assert.Empty(await Store().ListAsync());
        Assert.False(Directory.Exists(_dir) && Directory.EnumerateFiles(_dir).Any());
        h.Runs.Verify(x => x.FinishAsync(It.IsAny<Guid>(), DiagRunStatus.Error, It.IsAny<object?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public void TakesTheSharedInvasiveSlot()
    {
        var h = NewService(new FakeServer(1024), Store());
        using var capture = h.Jobs.TryStart(DiagJobKind.Capture, "ens192", null);

        Assert.Null(h.Service.Start(Plan(1_000_000, false), null));
    }

    [Theory]
    [InlineData(0, false, "error")]
    [InlineData(1000, true, "warn")]
    [InlineData(1000, false, "ok")]
    public void RunStatus_ZeroBytesIsError_CancelledIsWarn(long bytes, bool cancelled, string expected)
    {
        var r = new SpeedTestResult("ens192", 0x100, "Fake", "https://x", 4, bytes, 10, 1, 1, null, Array.Empty<double>(), false);
        Assert.Equal(expected, SpeedTestService.RunStatus(r, cancelled));
    }

    [Fact]
    public void StreamFailures_VoidTheTestOnlyWhenNothingArrived()
    {
        Assert.Equal((null, null), SpeedTestService.Explain([], 4, 0));
        Assert.Equal(("HTTP 404", null), SpeedTestService.Explain(["HTTP 404"], 4, 0));

        var (error, warning) = SpeedTestService.Explain(["reset"], 4, 5_000_000);
        Assert.Null(error);
        Assert.Contains("1 of 4", warning);
    }

    [Fact]
    public void Mbps_IsDecimalMegabits() => Assert.Equal(80, SpeedTestService.Mbps(10_000_000, 1));

    [Fact]
    public void Registry_PublishesTheLiveResult_AndKeepsItAfterFailure()
    {
        var reg = new DiagnosticJobRegistry(NullLogger<DiagnosticJobRegistry>.Instance);
        var handle = reg.TryStart(DiagJobKind.SpeedTest, "ens192", null)!;
        var partial = new SpeedTestResult("ens192", 0x100, "Fake", "https://x", 4, 3_000_000, 1, 24, 24, 12, [24.0], false);

        handle.Report(partial);
        Assert.Equal(3, reg.Get(handle.Id)!.ItemCount);           // megabytes so far
        Assert.Same(partial, reg.Get(handle.Id)!.SpeedTest);

        handle.Fail("reset by peer");
        handle.Dispose();
        var done = reg.Get(handle.Id)!;
        Assert.Equal(DiagJobState.Failed, done.State);
        Assert.Same(partial, done.SpeedTest);
    }

    // ───────────────────────── full download ─────────────────────────

    private static SpeedTestPlan FullPlan(bool keep, int streams = 3, int seconds = 30) =>
        new("ens224", 0x200, "Fake ISO", new Uri("https://mirror.example.org/iso/Distro-DVD-x86_64.iso"),
            seconds, 100_000_000_000, streams, keep, SpeedTestMode.FullFile);

    private static byte At(long offset) => (byte)(offset % 251);

    /// <summary>
    /// A mirror: honours Range (or not), can drop the first body mid-way, can be slow.
    /// Byte <c>i</c> of the file is <c>i % 251</c>, so any misplaced chunk shows.
    /// </summary>
    private sealed class MirrorServer(long size, bool ranges = true, long dropFirstAfter = -1, int delayMsPerRead = 0) : HttpMessageHandler
    {
        private int _dropped;
        public int Requests;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
        {
            Interlocked.Increment(ref Requests);
            long from = 0, to = size - 1;
            var partial = ranges && request.Headers.Range?.Ranges.FirstOrDefault() is { } r;
            if (partial)
            {
                var r0 = request.Headers.Range!.Ranges.First();
                from = r0.From ?? 0;
                to = Math.Min(size - 1, r0.To ?? size - 1);
            }
            var drop = dropFirstAfter >= 0 && to - from + 1 > dropFirstAfter && Interlocked.Exchange(ref _dropped, 1) == 0
                ? dropFirstAfter : -1;
            var resp = new HttpResponseMessage(partial ? HttpStatusCode.PartialContent : HttpStatusCode.OK)
            {
                Content = new StreamContent(new PatternStream(from, to - from + 1, drop, delayMsPerRead)),
            };
            resp.Content.Headers.ContentLength = to - from + 1;
            if (partial) resp.Content.Headers.ContentRange = new System.Net.Http.Headers.ContentRangeHeaderValue(from, to, size);
            return Task.FromResult(resp);
        }
    }

    private sealed class PatternStream(long start, long length, long dropAfter, int delayMs) : Stream
    {
        private long _pos;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => length;
        public override long Position { get => _pos; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException("async only");

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
        {
            if (delayMs > 0) await Task.Delay(delayMs, ct);
            if (dropAfter >= 0 && _pos >= dropAfter) throw new IOException("connection reset by peer");
            var n = (int)Math.Min(buffer.Length, length - _pos);
            if (dropAfter >= 0) n = (int)Math.Min(n, dropAfter - _pos);
            for (var i = 0; i < n; i++) buffer.Span[i] = At(start + _pos + i);
            _pos += n;
            return n;
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct) =>
            ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();
    }

    private async Task AssertPatternAsync(SpeedTestFile file, long size)
    {
        var opened = await Store().OpenReadAsync(file.Id);
        Assert.NotNull(opened);
        await using var content = opened.Value.Content;
        var buf = new byte[1 << 16];
        long offset = 0;
        int n;
        while ((n = await content.ReadAsync(buf)) > 0)
        {
            for (var i = 0; i < n; i++)
                if (buf[i] != At(offset + i)) Assert.Fail($"byte {offset + i} is {buf[i]}, expected {At(offset + i)}");
            offset += n;
        }
        Assert.Equal(size, offset);
    }

    [Fact]
    public async Task FullFile_FetchesEveryByteOnce_InChunks_AndKeepsAnExactCopyUnderItsOwnName()
    {
        const long size = 20L << 20;   // 20 MiB → three 8 MiB-floor chunks
        var server = new MirrorServer(size);
        var h = NewService(server, Store());

        var id = h.Service.Start(FullPlan(keep: true), "marvin")!.Value;
        var job = await WaitAsync(h.Jobs, id);

        Assert.Equal(DiagJobState.Completed, job.State);
        var r = job.SpeedTest!;
        Assert.True(r.Complete);
        Assert.Equal(size, r.Bytes);           // once, not once per connection
        Assert.Equal(size, r.TotalBytes);
        Assert.Equal(0, r.Reconnects);
        Assert.Null(r.Warning);

        var file = Assert.IsType<SpeedTestFile>(r.File);
        Assert.Equal("Distro-DVD-x86_64.iso", file.FileName);
        Assert.True(file.Complete);
        await AssertPatternAsync(file, size);
        h.Runs.Verify(x => x.FinishAsync(It.IsAny<Guid>(), DiagRunStatus.Ok, It.IsAny<object?>(), It.Is<string?>(s => s!.StartsWith("Full download")), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task FullFile_ADroppedConnectionResumesItsChunk_AndTheFileIsStillExact()
    {
        const long size = 20L << 20;
        var server = new MirrorServer(size, dropFirstAfter: 3_000_000);
        var h = NewService(server, Store());

        var id = h.Service.Start(FullPlan(keep: true), null)!.Value;
        var r = (await WaitAsync(h.Jobs, id)).SpeedTest!;

        Assert.True(r.Complete);
        Assert.Equal(1, r.Reconnects);
        Assert.Equal(size, r.Bytes);   // the resumed request asked only for the rest
        await AssertPatternAsync(r.File!, size);
    }

    [Fact]
    public async Task FullFile_WithoutRangeSupport_UsesOneConnection_AndSaysSo()
    {
        const long size = 5L << 20;
        var server = new MirrorServer(size, ranges: false);
        var h = NewService(server, Store());

        var id = h.Service.Start(FullPlan(keep: true, streams: 4), null)!.Value;
        var r = (await WaitAsync(h.Jobs, id)).SpeedTest!;

        Assert.True(r.Complete);
        Assert.Equal(size, r.Bytes);
        Assert.Contains("byte ranges", r.Warning);
        Assert.Equal(2, server.Requests);   // the probe plus one body
        await AssertPatternAsync(r.File!, size);
    }

    [Fact]
    public async Task FullFile_HittingTheTimeLimit_KeepsNothing_AndWarns()
    {
        var server = new MirrorServer(20L << 20, delayMsPerRead: 100);
        var h = NewService(server, Store());

        var id = h.Service.Start(FullPlan(keep: true, seconds: 1), null)!.Value;
        var job = await WaitAsync(h.Jobs, id);
        var r = job.SpeedTest!;

        Assert.Equal(DiagJobState.Completed, job.State);
        Assert.False(r.Complete);
        Assert.True(r.Bytes > 0);
        Assert.Null(r.File);
        Assert.Contains("not kept", r.Warning);
        Assert.Empty(await Store().ListAsync());
        Assert.False(Directory.EnumerateFiles(_dir).Any());   // no half ISO left behind
        h.Runs.Verify(x => x.FinishAsync(It.IsAny<Guid>(), DiagRunStatus.Warn, It.IsAny<object?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task FullFile_KeptFileAboveTheQuota_IsRefusedBeforeAnyByteLands()
    {
        var server = new MirrorServer(20L << 20);
        var h = NewService(server, Store(quotaMb: 1));

        var id = h.Service.Start(FullPlan(keep: true), null)!.Value;
        var job = await WaitAsync(h.Jobs, id);

        Assert.Equal(DiagJobState.Failed, job.State);
        Assert.Contains("quota", job.Message);
        Assert.Equal(1, server.Requests);   // only the size probe
    }

    [Fact]
    public void Chunks_CoverTheFileExactly_WithinTheSizeBounds()
    {
        foreach (var total in new[] { 1L, 5L << 20, 4_700_000_000L, 10_000_000_007L })
        {
            var chunks = SpeedTestService.Chunks(total, 4);
            Assert.Equal(0, chunks[0].Start);
            Assert.Equal(total - 1, chunks[^1].End);
            for (var i = 1; i < chunks.Count; i++) Assert.Equal(chunks[i - 1].End + 1, chunks[i].Start);
            Assert.All(chunks.SkipLast(1), c => Assert.InRange(c.End - c.Start + 1, 8L << 20, 256L << 20));
        }
    }

    [Fact]
    public void Stability_SkipsWarmup_AndCountsStallsOnlyAfterTheFirstByte()
    {
        var (lowest, stalls) = SpeedTestService.Stability([0, 0, 50, 300, 280, 0, 310, 0]);
        Assert.Equal(0, lowest);     // seconds 4+ include a stall
        Assert.Equal(2, stalls);     // the two leading zeros are connecting, not stalling

        Assert.Equal((290.0, 0), SpeedTestService.Stability([10, 100, 200, 300, 290, 305]));
    }

    [Theory]
    [InlineData("https://download.opensuse.org/tumbleweed/iso/openSUSE-Tumbleweed-DVD-x86_64-Current.iso", "openSUSE-Tumbleweed-DVD-x86_64-Current.iso")]
    [InlineData("https://speed.cloudflare.com/__down?bytes=100000000", null)]
    [InlineData("https://x.example.com/a%20b.iso", null)]
    [InlineData("https://x.example.com/", null)]
    public void SafeFileName_KeepsOnlyPlainNames(string url, string? expected) =>
        Assert.Equal(expected, SpeedTestService.SafeFileName(new Uri(url)));

    // ───────────────────────── kept files ─────────────────────────

    private async Task<Guid> CommitAsync(SpeedTestStore store, DateTime created, TimeSpan life)
    {
        var id = Guid.NewGuid();
        await File.WriteAllBytesAsync(store.PartPathFor(id), [1, 2, 3]);
        await store.CommitAsync(Meta(id, created, life));
        return id;
    }

    [Fact]
    public async Task ExpiredFile_IsNotListedOrServed_EvenBeforeTheSweep()
    {
        var store = Store();
        var live = await CommitAsync(store, DateTime.UtcNow, TimeSpan.FromHours(24));
        var dead = await CommitAsync(store, DateTime.UtcNow.AddHours(-25), TimeSpan.FromHours(24));

        Assert.Equal([live], (await store.ListAsync()).Select(f => f.Id));
        Assert.Null(await store.OpenReadAsync(dead));
        Assert.Null(await store.GetAsync(dead));
    }

    [Fact]
    public async Task Sweep_DeletesExpiredPairs_AndPartsOnlyAtStartup_AndNeverForeignFiles()
    {
        var store = Store();
        var live = await CommitAsync(store, DateTime.UtcNow, TimeSpan.FromHours(24));
        var dead = await CommitAsync(store, DateTime.UtcNow.AddHours(-25), TimeSpan.FromHours(24));
        var running = Guid.NewGuid();
        await File.WriteAllBytesAsync(store.PartPathFor(running), [9]);
        var foreign = Path.Combine(_dir, "README.txt");
        await File.WriteAllTextAsync(foreign, "not ours");

        await store.SweepAsync(includeInProgress: false);
        Assert.False(File.Exists(Path.Combine(_dir, dead.ToString("N") + ".bin")));
        Assert.False(File.Exists(Path.Combine(_dir, dead.ToString("N") + ".json")));
        Assert.True(File.Exists(Path.Combine(_dir, running.ToString("N") + ".part")));   // a test may be writing it
        Assert.NotNull(await store.GetAsync(live));

        await store.SweepAsync(includeInProgress: true);
        Assert.False(File.Exists(Path.Combine(_dir, running.ToString("N") + ".part")));
        Assert.True(File.Exists(foreign));
        Assert.NotNull(await store.GetAsync(live));
    }

    [Fact]
    public async Task Sweep_RemovesASettledPayloadWithoutMetadata()
    {
        var store = Store();
        var id = Guid.NewGuid();
        var orphan = Path.Combine(_dir, id.ToString("N") + ".bin");
        Directory.CreateDirectory(_dir);
        await File.WriteAllBytesAsync(orphan, [1]);

        await store.SweepAsync(false);
        Assert.True(File.Exists(orphan));   // could be mid-commit

        File.SetLastWriteTimeUtc(orphan, DateTime.UtcNow.AddHours(-1));
        await store.SweepAsync(false);
        Assert.False(File.Exists(orphan));
    }

    [Fact]
    public async Task Capacity_RefusesWhatCouldExceedTheQuota()
    {
        var store = Store(quotaMb: 1);
        Assert.Null(store.CheckCapacity(500_000));

        await CommitAsync(store, DateTime.UtcNow, TimeSpan.FromHours(24));   // 3 bytes used
        Assert.Contains("quota", store.CheckCapacity(1_000_000));
    }

    [Fact]
    public async Task Delete_RemovesBothHalves()
    {
        var store = Store();
        var id = await CommitAsync(store, DateTime.UtcNow, TimeSpan.FromHours(24));

        Assert.True(store.Delete(id));
        Assert.Null(await store.GetAsync(id));
        Assert.False(store.Delete(id));
    }

    // ───────────────────────── URL guard ─────────────────────────

    private static readonly DiagnosticInputValidator V = new();

    [Theory]
    [InlineData("https://speed.cloudflare.com/__down?bytes=100000000")]
    [InlineData("http://speedtest.example.net:8080/1GB.bin")]
    [InlineData("https://8.8.8.8/file.bin")]
    public void TestUrl_AcceptsPublicHttpUrls(string url) => Assert.True(V.TryTestUrl(url, out _, out _));

    [Theory]
    [InlineData("")]
    [InlineData("ftp://speed.example.com/1GB.bin")]
    [InlineData("file:///etc/shadow")]
    [InlineData("https://user:pass@speed.example.com/x")]
    [InlineData("http://192.168.1.1/x")]
    [InlineData("http://10.0.0.5/x")]
    [InlineData("http://127.0.0.1:5000/x")]
    [InlineData("http://169.254.169.254/latest/meta-data")]
    [InlineData("http://[::1]/x")]
    [InlineData("http://localhost/x")]
    [InlineData("speed.example.com/1GB.bin")]
    public void TestUrl_RefusesEverythingElse(string url) => Assert.False(V.TryTestUrl(url, out _, out _));

    [Theory]
    [InlineData("1.1.1.1", true)]
    [InlineData("100.64.0.1", false)]
    [InlineData("172.20.0.1", false)]
    [InlineData("172.32.0.1", true)]
    [InlineData("224.0.0.1", false)]
    [InlineData("fd00::1", false)]
    [InlineData("2606:4700::1111", true)]
    [InlineData("::ffff:192.168.1.1", false)]
    public void PublicAddress(string ip, bool expected) => Assert.Equal(expected, V.IsPublicAddress(IPAddress.Parse(ip)));
}
