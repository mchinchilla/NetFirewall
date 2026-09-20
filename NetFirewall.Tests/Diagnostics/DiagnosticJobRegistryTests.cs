using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Diagnostics.Jobs;

namespace NetFirewall.Tests.Diagnostics;

/// <summary>
/// One invasive job box-wide, and a job that can never get stuck on "running":
/// both are safety properties, not conveniences.
/// </summary>
public class DiagnosticJobRegistryTests
{
    private static DiagnosticJobRegistry New() => new(NullLogger<DiagnosticJobRegistry>.Instance);

    [Fact]
    public void OnlyOneInvasiveJobAtATime_AcrossKinds()
    {
        var reg = New();
        using var trace = reg.TryStart(DiagJobKind.Trace, "wg0", "marvin");
        Assert.NotNull(trace);

        // A capture must be refused while a trace holds the slot, and vice versa.
        Assert.Null(reg.TryStart(DiagJobKind.Capture, "ens192", "marvin"));
        Assert.Equal(trace.Id, reg.Current!.Id);
    }

    [Fact]
    public void SlotIsReleasedWhenTheHandleIsDisposed()
    {
        var reg = New();
        var first = reg.TryStart(DiagJobKind.Trace, "a", null)!;
        first.Complete(new TraceResult(Array.Empty<TraceEvent>(), "spec", false, 0));
        first.Dispose();

        Assert.Null(reg.Current);
        using var second = reg.TryStart(DiagJobKind.Capture, "b", null);
        Assert.NotNull(second);
    }

    [Fact]
    public void CompletedJobKeepsItsResultAndStopsBeingRunning()
    {
        var reg = New();
        var handle = reg.TryStart(DiagJobKind.Trace, "wg0", "marvin")!;
        handle.Progress(3);
        var events = new[] { new TraceEvent("1", "ip", "filter", "input", "verdict", "accept", "raw") };
        handle.Complete(new TraceResult(events, "ip saddr 1.2.3.4", false, 0));
        handle.Dispose();

        var snap = reg.Get(handle.Id)!;
        Assert.Equal(DiagJobState.Completed, snap.State);
        Assert.False(snap.IsRunning);
        Assert.Equal(1, snap.ItemCount);
        Assert.NotNull(snap.Trace);
        Assert.NotNull(snap.FinishedAtUtc);
    }

    [Fact]
    public void DisposingWithoutReporting_MarksTheJobFailed_NotStuckRunning()
    {
        var reg = New();
        var handle = reg.TryStart(DiagJobKind.Capture, "ens192", null)!;
        handle.Dispose();   // the exception path

        var snap = reg.Get(handle.Id)!;
        Assert.Equal(DiagJobState.Failed, snap.State);
        Assert.Contains("unexpectedly", snap.Message);
    }

    [Fact]
    public void Cancel_SignalsTheToken_AndTheResultIsKeptAsCancelled()
    {
        var reg = New();
        var handle = reg.TryStart(DiagJobKind.Trace, "wg0", null)!;

        Assert.True(reg.Cancel(handle.Id));
        Assert.True(handle.Token.IsCancellationRequested);

        handle.Complete(new TraceResult(Array.Empty<TraceEvent>(), "spec", false, 0));
        handle.Dispose();
        Assert.Equal(DiagJobState.Cancelled, reg.Get(handle.Id)!.State);
    }

    [Fact]
    public void CancelUnknownOrFinishedJob_IsFalse()
    {
        var reg = New();
        Assert.False(reg.Cancel(Guid.NewGuid()));

        var handle = reg.TryStart(DiagJobKind.Trace, "x", null)!;
        handle.Complete(new TraceResult(Array.Empty<TraceEvent>(), "s", false, 0));
        handle.Dispose();
        Assert.False(reg.Cancel(handle.Id));
    }

    [Fact]
    public void Recent_ListsNewestFirst()
    {
        var reg = New();
        for (var i = 0; i < 3; i++)
        {
            var h = reg.TryStart(DiagJobKind.Trace, $"job{i}", null)!;
            h.Complete(new TraceResult(Array.Empty<TraceEvent>(), "s", false, 0));
            h.Dispose();
        }
        var recent = reg.Recent(10);
        Assert.Equal(3, recent.Count);
        Assert.Equal("job2", recent[0].Subject);
    }
}
