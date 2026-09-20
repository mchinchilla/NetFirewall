using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics.Jobs;

public sealed class DiagnosticJobRegistry : IDiagnosticJobRegistry, IDisposable
{
    /// <summary>How long a finished job stays readable before it is swept.</summary>
    private static readonly TimeSpan Retention = TimeSpan.FromMinutes(30);
    private const int MaxRemembered = 20;

    private readonly ConcurrentDictionary<Guid, Entry> _jobs = new();
    private readonly ILogger<DiagnosticJobRegistry> _logger;
    private int _slotTaken;
    private Guid _current;

    public DiagnosticJobRegistry(ILogger<DiagnosticJobRegistry> logger) => _logger = logger;

    public DiagJobSnapshot? Current => _current != Guid.Empty && _jobs.TryGetValue(_current, out var e) && e.State == DiagJobState.Running
        ? e.Snapshot()
        : null;

    public IDiagnosticJobHandle? TryStart(DiagJobKind kind, string subject, string? requestedBy)
    {
        Sweep();
        if (Interlocked.CompareExchange(ref _slotTaken, 1, 0) != 0) return null;

        var entry = new Entry(Guid.NewGuid(), kind, subject, requestedBy);
        _jobs[entry.Id] = entry;
        _current = entry.Id;
        _logger.LogInformation("Diagnostics job {Kind} {Id} started by {User} on {Subject}", kind, entry.Id, requestedBy ?? "?", subject);
        return new Handle(entry, this);
    }

    public DiagJobSnapshot? Get(Guid id) => _jobs.TryGetValue(id, out var e) ? e.Snapshot() : null;

    public IReadOnlyList<DiagJobSnapshot> Recent(int limit = 10) =>
        _jobs.Values.OrderByDescending(e => e.StartedAt).Take(Math.Clamp(limit, 1, MaxRemembered)).Select(e => e.Snapshot()).ToList();

    public bool Cancel(Guid id)
    {
        if (!_jobs.TryGetValue(id, out var e) || e.State != DiagJobState.Running) return false;
        e.RequestCancel();
        _logger.LogInformation("Diagnostics job {Id} cancellation requested", id);
        return true;
    }

    private void Release(Entry entry)
    {
        if (_current == entry.Id) _current = Guid.Empty;
        Interlocked.Exchange(ref _slotTaken, 0);
        Sweep();
    }

    private void Sweep()
    {
        var cutoff = DateTime.UtcNow - Retention;
        foreach (var (id, e) in _jobs)
        {
            if (e.State != DiagJobState.Running && (e.FinishedAt ?? e.StartedAt) < cutoff && _jobs.TryRemove(id, out var gone))
                gone.Dispose();
        }
        // Hard cap, in case a burst outpaces the time-based sweep.
        foreach (var e in _jobs.Values.Where(x => x.State != DiagJobState.Running).OrderByDescending(x => x.StartedAt).Skip(MaxRemembered).ToList())
        {
            if (_jobs.TryRemove(e.Id, out var gone)) gone.Dispose();
        }
    }

    public void Dispose()
    {
        foreach (var e in _jobs.Values) e.Dispose();
        _jobs.Clear();
    }

    private sealed class Entry : IDisposable
    {
        private readonly CancellationTokenSource _cts = new();
        private readonly Stopwatch _sw = Stopwatch.StartNew();

        public Entry(Guid id, DiagJobKind kind, string subject, string? requestedBy)
        {
            Id = id; Kind = kind; Subject = subject; RequestedBy = requestedBy;
            StartedAt = DateTime.UtcNow;
        }

        public Guid Id { get; }
        public DiagJobKind Kind { get; }
        public string Subject { get; }
        public string? RequestedBy { get; }
        public DateTime StartedAt { get; }
        public DateTime? FinishedAt { get; private set; }
        public DiagJobState State { get; private set; } = DiagJobState.Running;

        private int _items;
        private bool _truncated;
        private string? _message;
        private TraceResult? _trace;
        private CaptureResult? _capture;
        private int _elapsedMs;

        public CancellationToken Token => _cts.Token;
        public bool CancellationRequested => _cts.IsCancellationRequested;
        public void RequestCancel() { try { _cts.Cancel(); } catch (ObjectDisposedException) { } }

        public void Progress(int items, bool truncated)
        {
            Volatile.Write(ref _items, items);
            if (truncated) _truncated = true;
        }

        public void Finish(DiagJobState state, string? message, TraceResult? trace, CaptureResult? capture)
        {
            if (State != DiagJobState.Running) return;
            _elapsedMs = (int)_sw.ElapsedMilliseconds;
            FinishedAt = DateTime.UtcNow;
            State = state;
            _message = message;
            _trace = trace;
            _capture = capture;
            if (trace is not null) { Volatile.Write(ref _items, trace.Events.Count); _truncated |= trace.Truncated; }
            if (capture is not null) { Volatile.Write(ref _items, capture.PacketsCaptured); _truncated |= capture.ReachedLimit; }
        }

        public DiagJobSnapshot Snapshot() => new(
            Id, Kind, State, StartedAt, FinishedAt,
            State == DiagJobState.Running ? (int)_sw.ElapsedMilliseconds : _elapsedMs,
            RequestedBy, Subject, Volatile.Read(ref _items), _truncated, _message, _trace, _capture);

        public void Dispose() { try { _cts.Dispose(); } catch { /* best effort */ } }
    }

    private sealed class Handle : IDiagnosticJobHandle
    {
        private readonly Entry _entry;
        private readonly DiagnosticJobRegistry _owner;
        private int _disposed;

        public Handle(Entry entry, DiagnosticJobRegistry owner) { _entry = entry; _owner = owner; }

        public Guid Id => _entry.Id;
        public CancellationToken Token => _entry.Token;
        public bool CancellationRequested => _entry.CancellationRequested;

        public void Progress(int itemCount, bool truncated = false) => _entry.Progress(itemCount, truncated);

        public void Complete(TraceResult result) =>
            _entry.Finish(_entry.CancellationRequested ? DiagJobState.Cancelled : DiagJobState.Completed, result.Error, result, null);

        public void Complete(CaptureResult result) =>
            _entry.Finish(_entry.CancellationRequested ? DiagJobState.Cancelled : DiagJobState.Completed, result.Error, null, result);

        public void Fail(string message) => _entry.Finish(DiagJobState.Failed, message, null, null);

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 1) return;
            // A job that ended without reporting anything (exception path) is a failure,
            // never a job stuck on "running" forever.
            _entry.Finish(DiagJobState.Failed, "The job ended unexpectedly.", null, null);
            _owner.Release(_entry);
        }
    }
}
