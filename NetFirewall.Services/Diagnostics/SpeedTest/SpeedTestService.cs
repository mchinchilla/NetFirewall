using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Win32.SafeHandles;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Diagnostics.Jobs;

namespace NetFirewall.Services.Diagnostics.SpeedTest;

public sealed partial class SpeedTestService : ISpeedTestService
{
    private const int BufferSize = 64 * 1024;

    /// <summary>A dropped connection is re-opened and its chunk resumed this many times in a row before the chunk is given up.</summary>
    internal const int MaxChunkRetries = 5;

    /// <summary>Seconds of TCP slow start left out of <see cref="SpeedTestResult.LowestMbps"/>.</summary>
    internal const int WarmupSeconds = 3;

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
        var kind = plan.Mode == SpeedTestMode.FullFile ? "full download" : "burst";
        var handle = _jobs.TryStart(DiagJobKind.SpeedTest, $"{plan.Wan} (0x{plan.Fwmark:x}) · {plan.SourceName} · {kind}", requestedBy);
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
            catch (SpeedTestAbort abort)
            {
                // An expected refusal (server status, too big, no room): a message, not a stack trace.
                _store.Discard(handle.Id);
                result = Empty(plan, abort.Message) with { TotalBytes = abort.TotalBytes };
            }
            catch (Exception ex) when (ex is OperationCanceledException && handle.CancellationRequested)
            {
                _store.Discard(handle.Id);
                result = Empty(plan, "Stopped before the download started.");
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
        var clock = Stopwatch.StartNew();

        var transfer = plan.Mode == SpeedTestMode.FullFile
            ? await StartFullFileAsync(handle.Id, plan, client, meter, clock, stop)
            : StartBurst(handle.Id, plan, client, meter, clock, stop);
        await using var sink = transfer.Sink;

        // One sample per whole second, published as a partial result for the live curve.
        var samples = new List<double>();
        var all = Task.WhenAll(transfer.Workers);
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
                handle.Report(Build(plan, meter, clock.Elapsed.TotalSeconds, samples.ToList(), transfer.Total, complete: false));
            }
        }

        var errors = (await all).OfType<string>().ToList();
        var seconds = clock.Elapsed.TotalSeconds;
        var rxAfter = await RxBytesAsync(plan.Wan);
        long? other = rxBefore is { } b && rxAfter is { } a && a >= b
            ? Math.Max(0, a - b - (long)(meter.Bytes * WireOverhead))
            : null;

        var complete = transfer.IsComplete();
        var (error, warning) = Explain(errors, plan.Streams, meter.Bytes);
        if (plan.Mode == SpeedTestMode.FullFile && !complete && meter.Bytes > 0)
            warning = Join(warning, IncompleteReason(meter.Bytes, transfer.Total, handle.CancellationRequested, plan));
        warning = Join(warning, transfer.Note);

        SpeedTestFile? file = null;
        if (sink is not null)
        {
            await sink.DisposeAsync();
            // A full download with holes is no ISO; only a whole one is worth keeping.
            var keep = sink.Written > 0 && (plan.Mode == SpeedTestMode.Burst || complete);
            if (keep)
                file = await KeepAsync(handle.Id, plan, sink, transfer, meter, seconds, complete, requestedBy);
            else
                _store.Discard(handle.Id);
            if (!keep && sink.Written > 0)
                warning = Join(warning, "The file was incomplete, so it was not kept.");
        }

        return Build(plan, meter, seconds, samples, transfer.Total, complete) with
        {
            OtherTrafficBytes = other, File = file, Error = error, Warning = warning,
        };
    }

    // ───────────────────────── burst ─────────────────────────

    private Transfer StartBurst(Guid id, SpeedTestPlan plan, HttpClient client, ThroughputMeter meter, Stopwatch clock, CancellationTokenSource stop)
    {
        var sink = plan.KeepFile ? new PayloadSink(_store.PartPathFor(id), preallocate: 0) : null;
        var workers = Enumerable.Range(0, plan.Streams)
            .Select(i => Task.Run(() => BurstWorkerAsync(client, plan.Url, meter, i == 0 ? sink : null, clock, stop)))
            .ToArray();
        return new Transfer(workers, sink, null, () => sink?.Done ?? false, null);
    }

    /// <summary>
    /// One burst connection: request the source again and again until the test stops.
    /// Returns null when it ended because the test did, or why it gave up.
    /// </summary>
    private static async Task<string?> BurstWorkerAsync(
        HttpClient client, Uri url, ThroughputMeter meter, PayloadSink? sink, Stopwatch clock, CancellationTokenSource stop)
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
                if (!resp.IsSuccessStatusCode) return StatusError(url, resp);

                await using var body = await resp.Content.ReadAsStreamAsync(ct);
                long got = 0;
                int n;
                while ((n = await body.ReadAsync(buffer.AsMemory(0, BufferSize), ct)) > 0)
                {
                    if (got == 0 && firstRequest) meter.FirstByte(clock.Elapsed - sentAt);
                    got += n;
                    // One writer, in order: the kept file is the first response, byte for byte.
                    if (sink is { Done: false }) await sink.WriteAsync(sink.Written, buffer.AsMemory(0, n), ct);
                    if (meter.Add(n)) stop.Cancel();   // byte cap reached: end the whole test
                }
                firstRequest = false;
                sink?.MarkComplete();
                if (got == 0) return $"{url.Host} sent an empty response.";
            }
            return null;
        }
        catch (Exception) when (ct.IsCancellationRequested)
        {
            return null;   // the deadline, the cap or the operator — a normal end, whatever the socket threw
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException)
        {
            return Describe(ex);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    // ───────────────────────── full download ─────────────────────────

    private async Task<Transfer> StartFullFileAsync(Guid id, SpeedTestPlan plan, HttpClient client, ThroughputMeter meter, Stopwatch clock, CancellationTokenSource stop)
    {
        var probe = await ProbeAsync(client, plan.Url, stop.Token);
        if (probe.Total is { } size && size > plan.MaxBytes)
            throw new SpeedTestAbort($"The file is {Gb(size)}, above the {Gb(plan.MaxBytes)} limit for one test.", size);
        if (plan.KeepFile)
        {
            if (probe.Total is not { } known)
                throw new SpeedTestAbort($"{plan.Url.Host} did not say how big the file is, so it cannot be checked against the disk quota. Run without keeping the file.");
            if (_store.CheckCapacity(known) is { } full)
                throw new SpeedTestAbort($"The file is {Gb(known)}. {full}", known);
        }

        // Preallocating reserves the space up front, so a full disk fails now, not 40 minutes in.
        var sink = plan.KeepFile ? new PayloadSink(_store.PartPathFor(id), probe.Total ?? 0) : null;

        if (probe.Ranges && probe.Total is { } total)
        {
            var queue = new ConcurrentQueue<Chunk>(Chunks(total, plan.Streams));
            var workers = Enumerable.Range(0, plan.Streams)
                .Select(_ => Task.Run(() => ChunkWorkerAsync(client, probe.Url, queue, meter, sink, clock, stop.Token)))
                .ToArray();
            return new Transfer(workers, sink, total, () => meter.CompletedBytes >= total, null);
        }

        // No range support (or no size): one connection reads the body to the end, and
        // a drop cannot be resumed. Say so, because it changes what the number means.
        var single = Task.Run(() => WholeBodyWorkerAsync(client, probe.Url, meter, sink, clock, stop.Token));
        var note = $"{plan.Url.Host} does not serve byte ranges, so the file came over one connection and a dropped connection could not be resumed.";
        return new Transfer([single], sink, probe.Total, () => meter.CompletedBytes > 0 && (probe.Total is null || meter.CompletedBytes >= probe.Total), note);
    }

    /// <summary>
    /// Ask for the first byte only. A 206 with a Content-Range length means the server
    /// splits the file; the final URL (after redirects to a mirror) is used for every
    /// chunk, so the chunks cannot land on different mirrors.
    /// </summary>
    private static async Task<Probe> ProbeAsync(HttpClient client, Uri url, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        req.Headers.Range = new RangeHeaderValue(0, 0);
        using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
        var final = resp.RequestMessage?.RequestUri ?? url;

        if (resp.StatusCode == HttpStatusCode.PartialContent && resp.Content.Headers.ContentRange is { HasLength: true } range)
            return new Probe(final, range.Length, Ranges: true);
        if (resp.IsSuccessStatusCode)
            return new Probe(final, resp.Content.Headers.ContentLength, Ranges: false);
        throw new SpeedTestAbort(StatusError(url, resp));
    }

    /// <summary>
    /// Pull chunks off the shared queue until it is empty. A dropped connection resumes
    /// its chunk from the last byte written; after <see cref="MaxChunkRetries"/> failures
    /// in a row the remainder goes back on the queue for another connection.
    /// </summary>
    private static async Task<string?> ChunkWorkerAsync(
        HttpClient client, Uri url, ConcurrentQueue<Chunk> queue, ThroughputMeter meter, PayloadSink? sink, Stopwatch clock, CancellationToken ct)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        var first = true;
        try
        {
            while (queue.TryDequeue(out var chunk))
            {
                var pos = chunk.Start;
                var failures = 0;
                while (pos <= chunk.End)
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        using var req = new HttpRequestMessage(HttpMethod.Get, url);
                        req.Headers.Range = new RangeHeaderValue(pos, chunk.End);
                        var sentAt = clock.Elapsed;
                        using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
                        if (IsTransient(resp.StatusCode))
                            throw new HttpRequestException($"{url.Host} answered HTTP {(int)resp.StatusCode}", null, resp.StatusCode);
                        if (resp.StatusCode != HttpStatusCode.PartialContent)
                        {
                            queue.Enqueue(chunk with { Start = pos });
                            return resp.IsSuccessStatusCode
                                ? $"{url.Host} stopped honouring byte ranges mid-download (HTTP {(int)resp.StatusCode})."
                                : StatusError(url, resp);
                        }

                        await using var body = await resp.Content.ReadAsStreamAsync(ct);
                        int n;
                        while (pos <= chunk.End &&
                               (n = await body.ReadAsync(buffer.AsMemory(0, (int)Math.Min(BufferSize, chunk.End - pos + 1)), ct)) > 0)
                        {
                            if (first) { meter.FirstByte(clock.Elapsed - sentAt); first = false; }
                            if (sink is not null) await sink.WriteAsync(pos, buffer.AsMemory(0, n), ct);
                            pos += n;
                            failures = 0;   // progress resets the streak: only consecutive failures give up
                            meter.Add(n);
                        }
                        if (pos <= chunk.End) throw new IOException($"{url.Host} closed the connection mid-chunk.");
                    }
                    catch (Exception ex) when (!ct.IsCancellationRequested && ex is HttpRequestException or IOException)
                    {
                        if (++failures > MaxChunkRetries)
                        {
                            queue.Enqueue(chunk with { Start = pos });
                            return Describe(ex);
                        }
                        meter.Reconnected();
                        await Task.Delay(TimeSpan.FromSeconds(failures), ct);
                    }
                }
                meter.ChunkDone(chunk.End - chunk.Start + 1);
            }
            return null;
        }
        catch (Exception) when (ct.IsCancellationRequested)
        {
            return null;   // time limit or operator — whatever the socket threw
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async Task<string?> WholeBodyWorkerAsync(
        HttpClient client, Uri url, ThroughputMeter meter, PayloadSink? sink, Stopwatch clock, CancellationToken ct)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
        try
        {
            var sentAt = clock.Elapsed;
            using var resp = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!resp.IsSuccessStatusCode) return StatusError(url, resp);

            await using var body = await resp.Content.ReadAsStreamAsync(ct);
            long pos = 0;
            int n;
            while ((n = await body.ReadAsync(buffer.AsMemory(0, BufferSize), ct)) > 0)
            {
                if (pos == 0) meter.FirstByte(clock.Elapsed - sentAt);
                if (sink is not null) await sink.WriteAsync(pos, buffer.AsMemory(0, n), ct);
                pos += n;
                meter.Add(n);
            }
            meter.ChunkDone(pos);   // EOF reached: the body is whole
            return null;
        }
        catch (Exception) when (ct.IsCancellationRequested)
        {
            return null;
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException)
        {
            return Describe(ex);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    // ───────────────────────── keeping the file ─────────────────────────

    private async Task<SpeedTestFile?> KeepAsync(Guid id, SpeedTestPlan plan, PayloadSink sink, Transfer transfer, ThroughputMeter meter,
        double seconds, bool complete, string? requestedBy)
    {
        var now = DateTime.UtcNow;
        var name = plan.Mode == SpeedTestMode.FullFile
            ? SafeFileName(plan.Url) ?? $"download-{plan.Wan}-{now:yyyyMMdd-HHmmss}.bin"
            : $"speedtest-{plan.Wan}-{now:yyyyMMdd-HHmmss}.bin";
        // Burst: one sequential writer. Full download: every connection writes, so
        // compare against all of their time together.
        var writerSeconds = plan.Mode == SpeedTestMode.FullFile ? seconds * transfer.Workers.Length : sink.ActiveSeconds;

        var meta = new SpeedTestFile(
            id, name,
            plan.Mode == SpeedTestMode.FullFile ? transfer.Total ?? sink.Written : sink.Written,
            complete,
            plan.Wan,
            plan.SourceName,
            Math.Round(Mbps(meter.Bytes, seconds), 1),
            now,
            now.AddHours(Math.Max(1, _opts.SpeedTestRetentionHours)),
            requestedBy,
            sink.WriteSeconds > 0 ? Math.Round(Mbps(sink.Written, sink.WriteSeconds), 1) : null,
            DiskLimited: writerSeconds > 0 && sink.WriteSeconds > writerSeconds * 0.5);

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
                Mode = plan.Mode.ToString(), plan.DurationSec, MaxMegabytes = plan.MaxBytes / 1_000_000, plan.Streams, plan.KeepFile,
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
        : cancelled || r.Warning is not null || (r.Mode == SpeedTestMode.FullFile && !r.Complete) ? DiagRunStatus.Warn
        : DiagRunStatus.Ok;

    internal static string Summary(SpeedTestResult r, bool cancelled)
    {
        if (r.Bytes == 0) return r.Error ?? "Nothing was downloaded.";
        var via = $"via {r.Wan} (0x{r.Fwmark:x}) from {r.Source}";
        if (r.Mode == SpeedTestMode.Burst)
            return $"{r.AvgMbps:0.#} Mbps avg, peak {r.PeakMbps:0.#} {via}" + (cancelled ? " — stopped early" : string.Empty);

        var what = r.Complete
            ? $"Full download of {Gb(r.TotalBytes ?? r.Bytes)} in {Clock(r.Seconds)}"
            : $"{r.ProgressPct ?? 0:0.#}% of {(r.TotalBytes is { } t ? Gb(t) : "the file")} in {Clock(r.Seconds)}" + (cancelled ? " (stopped)" : " (incomplete)");
        return $"{what}: {r.AvgMbps:0.#} Mbps avg, lowest {r.LowestMbps ?? 0:0.#}, {r.StallSeconds} stall s, {r.Reconnects} reconnect(s) {via}";
    }

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

    /// <summary>Split a file into range chunks: ~8 per connection so a slow one leaves only a short tail, 8–256 MB each.</summary>
    internal static IReadOnlyList<Chunk> Chunks(long total, int streams)
    {
        var size = Math.Clamp(total / (Math.Max(1, streams) * 8L), 8L << 20, 256L << 20);
        var list = new List<Chunk>();
        for (long start = 0; start < total; start += size)
            list.Add(new Chunk(start, Math.Min(total, start + size) - 1));
        return list;
    }

    /// <summary>Slowest second after warm-up, and seconds with nothing at all after the first byte.</summary>
    internal static (double? Lowest, int Stalls) Stability(IReadOnlyList<double> samples)
    {
        var steady = samples.Skip(WarmupSeconds).ToList();
        var firstByte = samples.ToList().FindIndex(s => s > 0);
        var stalls = firstByte < 0 ? 0 : samples.Skip(firstByte).Count(s => s == 0);
        return (steady.Count == 0 ? null : Math.Round(steady.Min(), 1), stalls);
    }

    internal static double Mbps(long bytes, double seconds) => seconds <= 0 ? 0 : bytes * 8 / seconds / 1_000_000;

    /// <summary>The source's own file name (an ISO keeps its name), or null when it is not a plain safe name.</summary>
    internal static string? SafeFileName(Uri url)
    {
        var name = Path.GetFileName(Uri.UnescapeDataString(url.AbsolutePath));
        return SafeNameRx().IsMatch(name) ? name : null;
    }

    private static string IncompleteReason(long bytes, long? total, bool cancelled, SpeedTestPlan plan)
    {
        var got = total is > 0 ? $"{bytes * 100.0 / total.Value:0.#}% of {Gb(total.Value)}" : Gb(bytes);
        return cancelled
            ? $"Stopped with {got} downloaded."
            : $"Only {got} arrived within the {plan.DurationSec / 60}-minute limit.";
    }

    private static SpeedTestResult Build(SpeedTestPlan plan, ThroughputMeter meter, double seconds, IReadOnlyList<double> samples, long? total, bool complete)
    {
        var (lowest, stalls) = Stability(samples);
        return new SpeedTestResult(plan.Wan, plan.Fwmark, plan.SourceName, plan.Url.ToString(), plan.Streams,
            meter.Bytes, Math.Round(seconds, 2),
            Math.Round(Mbps(meter.Bytes, seconds), 1),
            Math.Round(samples.Count == 0 ? Mbps(meter.Bytes, seconds) : samples.Max(), 1),
            meter.TtfbMs, samples.Select(s => Math.Round(s, 1)).ToList(),
            meter.ReachedCap,
            Mode: plan.Mode, TotalBytes: total, Complete: complete,
            LowestMbps: lowest, StallSeconds: stalls, Reconnects: meter.Reconnects);
    }

    private static SpeedTestResult Empty(SpeedTestPlan plan, string error) =>
        new(plan.Wan, plan.Fwmark, plan.SourceName, plan.Url.ToString(), plan.Streams, 0, 0, 0, 0, null,
            Array.Empty<double>(), false, Error: error, Mode: plan.Mode);

    private static bool IsTransient(HttpStatusCode code) => code is HttpStatusCode.TooManyRequests || (int)code >= 500;

    private static string StatusError(Uri url, HttpResponseMessage resp) =>
        $"{url.Host} answered HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}".TrimEnd();

    private static string Describe(Exception ex) =>
        ex.InnerException is { } inner ? $"{ex.Message} ({inner.Message})" : ex.Message;

    private static string? Join(string? a, string? b) =>
        string.IsNullOrEmpty(a) ? b : string.IsNullOrEmpty(b) ? a : $"{a} {b}";

    private static string Gb(long bytes) => bytes >= 1_000_000_000 ? $"{bytes / 1e9:0.##} GB" : $"{bytes / 1e6:0.#} MB";

    private static string Clock(double seconds) => TimeSpan.FromSeconds(Math.Round(seconds)).ToString(seconds >= 3600 ? @"h\:mm\:ss" : @"m\:ss");

    private async Task<long?> RxBytesAsync(string iface)
    {
        try { return (await _ifaces.GetAsync(iface)) is { Exists: true } h ? h.RxBytes : null; }
        catch (Exception ex) { _logger.LogDebug(ex, "rx counter for {Iface} unavailable", iface); return null; }
    }

    [GeneratedRegex(@"^[A-Za-z0-9][A-Za-z0-9._\-]{0,150}$")]
    private static partial Regex SafeNameRx();

    // ───────────────────────── moving parts ─────────────────────────

    internal sealed record Chunk(long Start, long End);

    private sealed record Probe(Uri Url, long? Total, bool Ranges);

    /// <summary>What a started transfer hands back to the shared sampling loop.</summary>
    private sealed record Transfer(Task<string?>[] Workers, PayloadSink? Sink, long? Total, Func<bool> IsComplete, string? Note);

    private sealed class SpeedTestAbort(string message, long? totalBytes = null) : Exception(message)
    {
        public long? TotalBytes { get; } = totalBytes;
    }

    /// <summary>Byte counter shared by every connection of one test. Thread-safe.</summary>
    internal sealed class ThroughputMeter(long cap)
    {
        private long _bytes;
        private long _completed;
        private int _reconnects;
        private long _ttfbTicks = long.MaxValue;

        public long Bytes => Interlocked.Read(ref _bytes);
        /// <summary>Bytes in chunks that finished — counts only whole pieces of the file.</summary>
        public long CompletedBytes => Interlocked.Read(ref _completed);
        public int Reconnects => Volatile.Read(ref _reconnects);
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

        public void ChunkDone(long length) => Interlocked.Add(ref _completed, length);

        public void Reconnected() => Interlocked.Increment(ref _reconnects);

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
    /// The kept file. Writes go to explicit offsets, so a burst's single writer appends
    /// and a full download's connections fill their own chunks. Time inside writes is
    /// summed across writers, so the result can say when the disk set the pace.
    /// </summary>
    internal sealed class PayloadSink : IAsyncDisposable
    {
        private readonly SafeFileHandle _file;
        private readonly Stopwatch _active = new();
        private long _written;
        private long _writeTicks;
        private int _disposed;

        public PayloadSink(string path, long preallocate)
        {
            _file = File.OpenHandle(path, FileMode.Create, FileAccess.Write, FileShare.None, FileOptions.Asynchronous, preallocate);
        }

        /// <summary>Burst only: the first response finished — stop writing, the file is a full copy.</summary>
        public bool Done { get; private set; }
        public long Written => Interlocked.Read(ref _written);
        public double WriteSeconds => TimeSpan.FromTicks(Interlocked.Read(ref _writeTicks)).TotalSeconds;
        /// <summary>Burst only: from the first write until the file was complete or the test ended.</summary>
        public double ActiveSeconds => _active.Elapsed.TotalSeconds;

        public async ValueTask WriteAsync(long offset, ReadOnlyMemory<byte> data, CancellationToken ct)
        {
            if (Done || Volatile.Read(ref _disposed) == 1) return;
            _active.Start();
            var started = Stopwatch.GetTimestamp();
            await RandomAccess.WriteAsync(_file, data, offset, ct);
            Interlocked.Add(ref _writeTicks, Stopwatch.GetElapsedTime(started).Ticks);
            Interlocked.Add(ref _written, data.Length);
        }

        public void MarkComplete()
        {
            if (Written == 0) return;
            Done = true;
            _active.Stop();
        }

        public ValueTask DisposeAsync()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 1) return ValueTask.CompletedTask;
            _active.Stop();
            _file.Dispose();
            return ValueTask.CompletedTask;
        }
    }
}
