using NetFirewall.Models.Firewall;
using NetFirewall.Services.Firewall;

namespace NetFirewall.Tests.Firewall;

public class ScheduleApplyPlannerTests
{
    private static FwSchedule Sched(Guid id, TimeSpan start, TimeSpan end, bool enabled = true)
        => new()
        {
            Id = id,
            Name = "s",
            DaysOfWeek = new[] { 0, 1, 2, 3, 4, 5, 6 },
            StartTime = start,
            EndTime = end,
            Timezone = "UTC",
            Enabled = enabled
        };

    private static FwFilterRule Rule(Guid id, Guid scheduleId, bool invert = false, bool enabled = true, string src = "10.0.0.5")
        => new()
        {
            Id = id,
            Chain = "forward",
            Action = "drop",
            Enabled = enabled,
            Priority = 2,
            ScheduleId = scheduleId,
            ScheduleInvert = invert,
            SourceAddresses = new[] { src }
        };

    [Fact]
    public void Fingerprint_ChangesWhenScheduleBecomesActive()
    {
        var sid = Guid.NewGuid();
        var sched = Sched(sid, TimeSpan.FromHours(9), TimeSpan.FromHours(17));
        var rule = Rule(Guid.NewGuid(), sid, invert: true);
        var before = new DateTimeOffset(2026, 4, 27, 8, 0, 0, TimeSpan.Zero);
        var inside = new DateTimeOffset(2026, 4, 27, 12, 0, 0, TimeSpan.Zero);

        var a = ScheduleApplyPlanner.Fingerprint(new[] { sched }, new[] { rule }, before);
        var b = ScheduleApplyPlanner.Fingerprint(new[] { sched }, new[] { rule }, inside);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Fingerprint_ChangesWhenScheduledRuleIsAdded()
    {
        var sid = Guid.NewGuid();
        var sched = Sched(sid, TimeSpan.FromHours(22), TimeSpan.FromHours(6));
        var now = new DateTimeOffset(2026, 4, 27, 12, 0, 0, TimeSpan.Zero);

        var empty = ScheduleApplyPlanner.Fingerprint(new[] { sched }, Array.Empty<FwFilterRule>(), now);
        var withRule = ScheduleApplyPlanner.Fingerprint(
            new[] { sched },
            new[] { Rule(Guid.NewGuid(), sid, invert: true) },
            now);
        Assert.NotEqual(empty, withRule);
    }

    [Fact]
    public void Fingerprint_ChangesWhenSourcesChange()
    {
        var sid = Guid.NewGuid();
        var rid = Guid.NewGuid();
        var sched = Sched(sid, TimeSpan.FromHours(22), TimeSpan.FromHours(6));
        var now = new DateTimeOffset(2026, 4, 27, 12, 0, 0, TimeSpan.Zero);

        var a = ScheduleApplyPlanner.Fingerprint(new[] { sched }, new[] { Rule(rid, sid, src: "10.0.0.5") }, now);
        var b = ScheduleApplyPlanner.Fingerprint(new[] { sched }, new[] { Rule(rid, sid, src: "10.0.0.6") }, now);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void Fingerprint_IgnoresUnscheduledRules()
    {
        var now = new DateTimeOffset(2026, 4, 27, 12, 0, 0, TimeSpan.Zero);
        var unscheduled = new FwFilterRule
        {
            Id = Guid.NewGuid(),
            Chain = "input",
            Action = "accept",
            Enabled = true,
            DestinationPorts = new[] { "22" }
        };
        var a = ScheduleApplyPlanner.Fingerprint(Array.Empty<FwSchedule>(), Array.Empty<FwFilterRule>(), now);
        var b = ScheduleApplyPlanner.Fingerprint(Array.Empty<FwSchedule>(), new[] { unscheduled }, now);
        Assert.Equal(a, b);
    }

    [Fact]
    public void NextEdge_UsesReferencedScheduleOnly()
    {
        var used = Guid.NewGuid();
        var unused = Guid.NewGuid();
        var now = new DateTimeOffset(2026, 4, 27, 8, 0, 0, TimeSpan.Zero);
        var schedules = new[]
        {
            Sched(used, TimeSpan.FromHours(22), TimeSpan.FromHours(6)),
            Sched(unused, TimeSpan.FromHours(9), TimeSpan.FromHours(10))
        };
        var rules = new[] { Rule(Guid.NewGuid(), used, invert: true) };

        var edge = ScheduleApplyPlanner.NextEdge(schedules, rules, now);
        Assert.Equal(new DateTimeOffset(2026, 4, 27, 22, 0, 0, TimeSpan.Zero), edge);
    }

    [Fact]
    public void DelayUntil_NearEdge_SleepsUntilSlackAfterEdge()
    {
        var now = new DateTimeOffset(2026, 4, 27, 21, 59, 57, TimeSpan.Zero);
        var edge = new DateTimeOffset(2026, 4, 27, 22, 0, 0, TimeSpan.Zero);
        var delay = ScheduleApplyPlanner.DelayUntil(now, edge);
        Assert.Equal(TimeSpan.FromSeconds(3) + ScheduleApplyPlanner.EdgeSlack, delay);
    }

    [Fact]
    public void DelayUntil_FarEdge_CapsAtMaxTick()
    {
        var now = new DateTimeOffset(2026, 4, 27, 12, 0, 0, TimeSpan.Zero);
        var edge = new DateTimeOffset(2026, 4, 27, 22, 0, 0, TimeSpan.Zero);
        var delay = ScheduleApplyPlanner.DelayUntil(now, edge);
        Assert.Equal(ScheduleApplyPlanner.MaxTick, delay);
    }

    [Fact]
    public void DelayUntil_NoEdge_CapsAtMaxTick()
    {
        var now = new DateTimeOffset(2026, 4, 27, 12, 0, 0, TimeSpan.Zero);
        Assert.Equal(ScheduleApplyPlanner.MaxTick, ScheduleApplyPlanner.DelayUntil(now, null));
    }
}
