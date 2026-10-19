using System.Buffers;
using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Diagnostics.Jobs;

namespace NetFirewall.Services.Diagnostics.SpeedTest;

public sealed class SpeedTestService : ISpeedTestService
{
    private const int BufferSize = 64 * 1024;

    /// <summary>
    /// Wire bytes per payload byte on a typical Ethernet + IPv4 + TCP + TLS download
    /// (1514-byte frames carrying ~1448 bytes of TCP payload, plus TLS records).
    /// Used only to estimate how much of the WAN counter was someone else's traffic.
    /// </summary>
    internal const double WireOverhead = 1.05;

    private readonly IDiagnosticJobRegistry _jobs;
    private readonly IMarkedHttpClientFactory _clients;
    private readonly ISpeedTestStore _store;
    private readonly IInterfaceHealthService _ifaces;
    private readonly IServiceScopeFactory _scopes;
    private readonly DiagnosticsOptions _opts;
    private readonly ILogger<SpeedTestService> _logger;

    public SpeedTestService(
        IDiagnosticJobRegistry jobs,
        IMarkedHttpClientFactory clients,
        ISpeedTestStore store,
        IInterfaceHealthService ifaces,
        IServiceScopeFactory scopes,
        IOptions<DiagnosticsOptions> opts,
        ILogger<SpeedTestService> logger)
    {
        _jobs = jobs;
        _clients = clients;
        _store = store;
        _ifaces = ifaces;
        _scopes = scopes;
        _opts = opts.Value;
        _logger = logger;
    }

    public Guid? Start(SpeedTestPlan plan, string? requestedBy)
    {
        var handle = _jobs.TryStart(DiagJobKind.SpeedTest, $"{plan.Wan} (0x{plan.Fwmark:x}) · {plan.SourceName}", requestedBy);
        if (handle is null) return null;

        _ = Task.Run(() => RunAsync(handle, plan, requestedBy));
        return handle.Id;
    }

    private async Task RunAsync(IDiagnosticJobHandle handle, SpeedTestPlan plan, string? requestedBy)
    {
        using (handle)
        {
            var runId = await StartRunAsync(plan, requestedBy);
            SpeedTestResult result;
            try
            {
                result = await MeasureAsync(handle, plan, requestedBy);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Speed test job {Id} failed", handle.Id);
                _store.Discard(handle.Id);
                result = Empty(plan, ex.Message);
            }

            if (result is { Bytes: 0, Error: { } error })
            {
                // Keep the result (it names the source and mark) but show a failure, not a green 0 Mbps.
                handle.Report(result);
                handle.Fail(error);
            }
            else
            {
                handle.Complete(result);
            }
            await FinishRunAsync(runId, result, handle.CancellationRequested);
        }
    }

    private async Task<SpeedTestResult> MeasureAsync(IDiagnosticJobHandle handle, SpeedTestPlan plan, string? requestedBy)
    {
        using var client = _clients.Create(plan.Fwmark);
        using var stop = CancellationTokenSource.CreateLinkedTokenSource(handle.Token);
        stop.CancelAfter(TimeSpan.FromSeconds(plan.DurationSec));

        var rxBefore = await RxBytesAsync(plan.Wan);
        var meter = new ThroughputMeter(plan.MaxBytes);
        await using var sink = plan.KeepFile ? new FileSink(_store.PartPathFor(handle.Id)) : null;

        var clock = Stopwatch.StartNew();
        var workers = Enumerable.Range(0, plan.Streams)
            .Select(i => Task.Run(() => WorkerAsync(client, plan.Url, meter, i == 0 ? sink : null, clock, stop)))
            .ToArray();
        var all = Task.WhenAll(workers);

        // One sample per whole second, published as a partial result for the live curve.
        var samples = new List<double>();
        using (var tick = new PeriodicTimer(TimeSpan.FromSeconds(1)))
        {
            long last = 0;
            while (!all.IsCompleted)
            {
                var next = tick.WaitForNextTickAsync().AsTask();
                if (await Task.WhenAny(next, all) != next) break;
                var now = meter.Bytes;
                samples.Add(Mbps(now - last, 1));
                last = now;
                handle.Report(Build(plan, meter, clock.Elapsed.TotalSeconds, samples.ToList(), null, null, null));
            }
        }

        var errors = (await all).OfType<string>().ToList();
        var seconds = clock.Elapsed.TotalSeconds;
        var rxAfter = await RxBytesAsync(plan.Wan);
        long? other = rxBefore is { } b && rxAfter is { } a && a >= b
            ? Math.Max(0, a - b - (long)(meter.Bytes * WireOverhead))
            : null;

        SpeedTestFile? file = null;
        if (sink is not null)
            file = await KeepAsync(handle.Id, plan, sink, meter, seconds, requestedBy);

        var (error, warning) = Explain(errors, plan.Streams, meter.Bytes);
        return Build(plan, meter, seconds, samples, other, file, error) with { Warning = warning };
    }

    /// <summary>
    /// One connection: request the source again and again until the test stops.
    /// Returns null when it ended because the test did, or why it gave up.
    /// </summary>
    private static async Task<string?> WorkerAsync(
        HttpClient client, Uri url, ThroughputMeter meter, FileSink? sink, Stopwatch clock, CancellationTokenSource stop)
    {
        var ct = stop.Token;
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        var firstRequest = true;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var sentAt = clock.Elapsed;
                using var resp = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
                if (!resp.IsSuccessStatusCode)
                    return $"{url.Host} answered HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}".TrimEnd();

                await using var body = await resp.Content.ReadAsStreamAsync(ct);
                long got = 0;
                int n;
                while ((n = await body.ReadAsync(buffer.AsMemory(0, BufferSize), ct)) > 0)
                {
                    if (got == 0 && firstRequest) meter.FirstByte(clock.Elapsed - sentAt);
                    got += n;
                    if (sink is { Done: false }) await sink.WriteAsync(buffer.AsMemory(0, n), ct);
                    if (meter.Add(n)) stop.Cancel();   // byte cap reached: end the whole test
                }
                firstRequest = false;
                sink?.MarkComplete();   // the first full response is the kept file
                if (got == 0) return $"{url.Host} sent an empty response.";
            }
            return null;
        }
        catch (Exception) when (ct.IsCancellationRequested)
        {
            return null;   // the deadline, the cap or the operator — a normal end, whatever the socket threw
        }
        catch (HttpRequestException ex)
        {
            return ex.InnerException is { } inner ? $"{ex.Message} ({inner.Message})" : ex.Message;
        }
        catch (IOException ex)
        {
            return ex.Message;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private async Task<SpeedTestFile?> KeepAsync(Guid id, SpeedTestPlan plan, FileSink sink, ThroughputMeter meter, double seconds, string? requestedBy)
    {
        await sink.DisposeAsync();
        if (sink.Written == 0)
        {
            _store.Discard(id);
            return null;
        }

        var now = DateTime.UtcNow;
        var meta = new SpeedTestFile(
            id,
            $"speedtest-{plan.Wan}-{now:yyyyMMdd-HHmmss}.bin",
            sink.Written,
            sink.Done,
            plan.Wan,
            plan.SourceName,
            Math.Round(Mbps(meter.Bytes, seconds), 1),
            now,
            now.AddHours(Math.Max(1, _opts.SpeedTestRetentionHours)),
            requestedBy,
            sink.WriteSeconds > 0 ? Math.Round(Mbps(sink.Written, sink.WriteSeconds), 1) : null,
            DiskLimited: sink.WriteSeconds > sink.ActiveSeconds * 0.5);

        try
        {
            await _store.CommitAsync(meta);
            return meta;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not keep speed-test file {Id}", id);
            _store.Discard(id);
            return null;
        }
    }

    // ───────────────────────── history ─────────────────────────

    private async Task<Guid?> StartRunAsync(SpeedTestPlan plan, string? requestedBy)
    {
        try
        {
            await using var scope = _scopes.CreateAsyncScope();
            var store = scope.ServiceProvider.GetRequiredService<IDiagnosticRunStore>();
            return await store.StartAsync(DiagTools.SpeedTest, plan.Wan, requestedBy, new
            {
                plan.Wan, Fwmark = $"0x{plan.Fwmark:x}", Source = plan.SourceName, Url = plan.Url.ToString(),
                plan.DurationSec, MaxMegabytes = plan.MaxBytes / 1_000_000, plan.Streams, plan.KeepFile,
            });
        }
        catch (Exception ex)
        {
            // History is a record, not a precondition: the test still runs.
            _logger.LogWarning(ex, "Could not record speed test start in diag_runs");
            return null;
        }
    }

    private async Task FinishRunAsync(Guid? runId, SpeedTestResult r, bool cancelled)
    {
        if (runId is null) return;
        try
        {
            await using var scope = _scopes.CreateAsyncScope();
            var store = scope.ServiceProvider.GetRequiredService<IDiagnosticRunStore>();
            await store.FinishAsync(runId.Value, RunStatus(r, cancelled), r, Summary(r, cancelled));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not record speed test result in diag_runs");
        }
    }

    // ───────────────────────── pure helpers ─────────────────────────

    internal static string RunStatus(SpeedTestResult r, bool cancelled) =>
        r.Bytes == 0 ? DiagRunStatus.Error
        : cancelled || r.Warning is not null ? DiagRunStatus.Warn
        : DiagRunStatus.Ok;

    internal static string Summary(SpeedTestResult r, bool cancelled) =>
        r.Bytes == 0
            ? r.Error ?? "Nothing was downloaded."
            : $"{r.AvgMbps:0.#} Mbps avg, peak {r.PeakMbps:0.#} via {r.Wan} (0x{r.Fwmark:x}) from {r.Source}"
              + (cancelled ? " — stopped early" : string.Empty);

    /// <summary>
    /// Stream failures void the test only when nothing arrived; otherwise they are a
    /// warning, because fewer streams than asked usually means a lower number.
    /// </summary>
    internal static (string? Error, string? Warning) Explain(IReadOnlyList<string> errors, int streams, long bytes)
    {
        if (errors.Count == 0) return (null, null);
        var first = errors[0];
        return bytes == 0
            ? (first, null)
            : (null, $"{errors.Count} of {streams} connection(s) failed during the test ({first}); the result may understate the link.");
    }

    internal static double Mbps(long bytes, double seconds) => seconds <= 0 ? 0 : bytes * 8 / seconds / 1_000_000;

    private static SpeedTestResult Build(SpeedTestPlan plan, ThroughputMeter meter, double seconds, IReadOnlyList<double> samples,
        long? other, SpeedTestFile? file, string? error) =>
        new(plan.Wan, plan.Fwmark, plan.SourceName, plan.Url.ToString(), plan.Streams,
            meter.Bytes, Math.Round(seconds, 2),
            Math.Round(Mbps(meter.Bytes, seconds), 1),
            Math.Round(samples.Count == 0 ? Mbps(meter.Bytes, seconds) : samples.Max(), 1),
            meter.TtfbMs, samples.Select(s => Math.Round(s, 1)).ToList(),
            meter.ReachedCap, other, file, error);

    private static SpeedTestResult Empty(SpeedTestPlan plan, string error) =>
        new(plan.Wan, plan.Fwmark, plan.SourceName, plan.Url.ToString(), plan.Streams, 0, 0, 0, 0, null,
            Array.Empty<double>(), false, Error: error);

    private async Task<long?> RxBytesAsync(string iface)
    {
        try { return (await _ifaces.GetAsync(iface)) is { Exists: true } h ? h.RxBytes : null; }
        catch (Exception ex) { _logger.LogDebug(ex, "rx counter for {Iface} unavailable", iface); return null; }
    }

    /// <summary>Byte counter shared by every connection of one test. Thread-safe.</summary>
    internal sealed class ThroughputMeter(long cap)
    {
        private long _bytes;
        private long _ttfbTicks = long.MaxValue;

        public long Bytes => Interlocked.Read(ref _bytes);
        public bool ReachedCap => Bytes >= cap;
        public double? TtfbMs
        {
            get
            {
                var t = Interlocked.Read(ref _ttfbTicks);
                return t == long.MaxValue ? null : Math.Round(TimeSpan.FromTicks(t).TotalMilliseconds, 1);
            }
        }

        /// <summary>Count <paramref name="n"/> bytes; true once the cap is reached.</summary>
        public bool Add(int n) => Interlocked.Add(ref _bytes, n) >= cap;

        /// <summary>Keep the fastest first-byte time across connections.</summary>
        public void FirstByte(TimeSpan delay)
        {
            var ticks = delay.Ticks;
            long seen;
            while (ticks < (seen = Interlocked.Read(ref _ttfbTicks)) &&
                   Interlocked.CompareExchange(ref _ttfbTicks, ticks, seen) != seen) { }
        }
    }

    /// <summary>
    /// Writes ONE connection's bytes to the kept file and times the writes, so the
    /// result can say when the disk, not the WAN, set the pace.
    /// </summary>
    internal sealed class FileSink : IAsyncDisposable
    {
        private readonly FileStream _fs;
        private readonly Stopwatch _active = new();
        private readonly Stopwatch _writing = new();
        private bool _disposed;

        public FileSink(string path)
        {
            _fs = new FileStream(path, new FileStreamOptions
            {
                Mode = FileMode.Create, Access = FileAccess.Write, Share = FileShare.None,
                Options = FileOptions.Asynchronous, BufferSize = 1 << 20,
            });
        }

        /// <summary>The first response finished: stop writing, the file is a full copy.</summary>
        public bool Done { get; private set; }
        public long Written { get; private set; }
        public double WriteSeconds => _writing.Elapsed.TotalSeconds;
        /// <summary>From the first write until the file was complete or the test ended.</summary>
        public double ActiveSeconds => _active.Elapsed.TotalSeconds;

        public async ValueTask WriteAsync(ReadOnlyMemory<byte> data, CancellationToken ct)
        {
            if (Done || _disposed) return;
            _active.Start();
            _writing.Start();
            try { await _fs.WriteAsync(data, ct); }
            finally { _writing.Stop(); }
            Written += data.Length;
        }

        public void MarkComplete()
        {
            if (Written == 0) return;
            Done = true;
            _active.Stop();
        }

        public async ValueTask DisposeAsync()
        {
            if (_disposed) return;
            _disposed = true;
            _active.Stop();
            await _fs.DisposeAsync();
        }
    }
}
