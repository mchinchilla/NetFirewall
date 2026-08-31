using NetFirewall.Models.Firewall;

namespace NetFirewall.Services.Firewall;

/// <summary>
/// Pure schedule-clock math for <see cref="ScheduleWatcherService"/>.
/// Decides <em>when</em> to re-apply and <em>whether</em> the live nft
/// snapshot would change — no IO, no time source of its own.
/// </summary>
public static class ScheduleApplyPlanner
{
    /// <summary>
    /// Upper bound on how long the watcher sleeps when the next clock edge
    /// is far away. Bounds lag after a schedule/rule write if the Postgres
    /// NOTIFY is lost, and recovers from clock jumps / DST.
    /// </summary>
    public static readonly TimeSpan MaxTick = TimeSpan.FromSeconds(15);

    /// <summary>
    /// Wake this far <em>after</em> the programmed instant so
    /// <see cref="FwSchedule.IsActiveAt"/> sees the new side of the boundary
    /// (start is inclusive, end is exclusive) even if the delay fires early.
    /// </summary>
    public static readonly TimeSpan EdgeSlack = TimeSpan.FromMilliseconds(250);

    public static string Fingerprint(
        IReadOnlyList<FwSchedule> schedules,
        IReadOnlyList<FwFilterRule> rules,
        DateTimeOffset utcNow)
    {
        var scheduled = rules.Where(r => r.Enabled && r.ScheduleId.HasValue).ToList();
        var referenced = scheduled.Select(r => r.ScheduleId!.Value).ToHashSet();
        var map = schedules.ToDictionary(s => s.Id);

        var active = referenced
            .Where(id => map.TryGetValue(id, out var s) && s.IsActiveAt(utcNow))
            .OrderBy(id => id)
            .Select(id => id.ToString("N"));

        var ruleBits = scheduled
            .OrderBy(r => r.Id)
            .Select(r => string.Join(':',
                r.Id.ToString("N"),
                r.ScheduleId!.Value.ToString("N"),
                r.ScheduleInvert ? "1" : "0",
                r.Chain,
                r.Action,
                r.Priority.ToString(),
                Join(r.SourceAddresses),
                Join(r.DestinationAddresses),
                Join(r.DestinationPorts),
                r.Protocol ?? "",
                r.InterfaceInId?.ToString("N") ?? "",
                r.InterfaceOutId?.ToString("N") ?? ""));

        return string.Join(',', active) + "#" + string.Join(';', ruleBits);
    }

    public static DateTimeOffset? NextEdge(
        IReadOnlyList<FwSchedule> schedules,
        IReadOnlyList<FwFilterRule> rules,
        DateTimeOffset utcNow)
    {
        var referenced = rules
            .Where(r => r.Enabled && r.ScheduleId.HasValue)
            .Select(r => r.ScheduleId!.Value)
            .ToHashSet();

        DateTimeOffset? soonest = null;
        foreach (var s in schedules)
        {
            if (!referenced.Contains(s.Id)) continue;
            var n = s.NextTransitionUtc(utcNow);
            if (n is { } t && (soonest is null || t < soonest))
                soonest = t;
        }

        return soonest;
    }

    public static TimeSpan DelayUntil(
        DateTimeOffset utcNow,
        DateTimeOffset? nextEdge,
        TimeSpan? maxTick = null,
        TimeSpan? slack = null)
    {
        var cap = maxTick ?? MaxTick;
        var pad = slack ?? EdgeSlack;
        if (nextEdge is null) return cap;

        var wait = nextEdge.Value + pad - utcNow;
        if (wait < TimeSpan.FromMilliseconds(50))
            wait = TimeSpan.FromMilliseconds(50);
        return wait < cap ? wait : cap;
    }

    private static string Join(string[]? values) =>
        values is { Length: > 0 } ? string.Join(',', values) : "";
}
