using RepoDb.Attributes;

namespace NetFirewall.Models.Firewall;

[Map("fw_schedules")]
public class FwSchedule
{
    [Map("id")]            public Guid     Id          { get; set; }
    [Map("name")]          public string   Name        { get; set; } = string.Empty;
    [Map("description")]   public string?  Description { get; set; }

    /// <summary>0=Sunday .. 6=Saturday (Postgres EXTRACT(DOW) convention).</summary>
    [Map("days_of_week")]  public int[]    DaysOfWeek  { get; set; } = new[] { 0, 1, 2, 3, 4, 5, 6 };

    /// <summary>Local time in <see cref="Timezone"/> when the rule turns ON.</summary>
    [Map("start_time")]    public TimeSpan StartTime   { get; set; } = TimeSpan.Zero;

    /// <summary>Local time in <see cref="Timezone"/> when the rule turns OFF (exclusive).</summary>
    [Map("end_time")]      public TimeSpan EndTime     { get; set; } = new TimeSpan(23, 59, 0);

    /// <summary>IANA timezone name (e.g. "America/New_York"). Default UTC.</summary>
    [Map("timezone")]      public string   Timezone    { get; set; } = "UTC";

    [Map("enabled")]       public bool     Enabled     { get; set; } = true;
    [Map("created_at")]    public DateTime CreatedAt   { get; set; }
    [Map("updated_at")]    public DateTime UpdatedAt   { get; set; }

    /// <summary>
    /// True iff "now" (in this schedule's timezone) falls inside the window
    /// AND the relevant day-of-week is enabled. A window with start &gt; end
    /// wraps midnight (e.g. 22:00–06:00): the starting day owns the night
    /// (Friday 22:00 through Saturday 06:00 if Friday is selected).
    /// </summary>
    public bool IsActiveAt(DateTimeOffset utcNow)
    {
        if (!Enabled) return false;
        TimeZoneInfo tz;
        try { tz = TimeZoneInfo.FindSystemTimeZoneById(Timezone); }
        catch { tz = TimeZoneInfo.Utc; }

        var local = TimeZoneInfo.ConvertTimeFromUtc(utcNow.UtcDateTime, tz);
        var dow = (int)local.DayOfWeek; // matches Postgres dow (0=Sun..6=Sat)
        var t = local.TimeOfDay;
        var overnight = StartTime > EndTime;

        if (!overnight)
            return DayEnabled(dow) && t >= StartTime && t < EndTime;

        // Overnight: [Start, 24h) on the start day, or [00:00, End) the next morning.
        if (t >= StartTime) return DayEnabled(dow);
        if (t < EndTime) return DayEnabled((dow + 6) % 7); // yesterday
        return false;
    }

    /// <summary>
    /// Next UTC instant at which <see cref="IsActiveAt"/> flips for this
    /// schedule (start inclusive or end exclusive). Null when the schedule
    /// is disabled, has no days, or has no future edge in the next week.
    /// The daemon watcher sleeps until this instant so nft is rebuilt at
    /// the programmed hour instead of up to a minute later.
    /// </summary>
    public DateTimeOffset? NextTransitionUtc(DateTimeOffset utcNow)
    {
        if (!Enabled) return null;
        if (DaysOfWeek is not { Length: > 0 }) return null;

        TimeZoneInfo tz;
        try { tz = TimeZoneInfo.FindSystemTimeZoneById(Timezone); }
        catch { tz = TimeZoneInfo.Utc; }

        var local = TimeZoneInfo.ConvertTimeFromUtc(utcNow.UtcDateTime, tz);
        var overnight = StartTime > EndTime;
        DateTimeOffset? soonest = null;

        // 8 days covers a full week plus an overnight spill into day 8.
        for (var offset = 0; offset <= 8; offset++)
        {
            var day = local.Date.AddDays(offset);
            var dow = (int)day.DayOfWeek;

            if (overnight)
            {
                if (DayEnabled(dow))
                    Consider(day.Add(StartTime));
                // End of yesterday's overnight window lands on this morning.
                if (DayEnabled((dow + 6) % 7))
                    Consider(day.Add(EndTime));
            }
            else if (DayEnabled(dow))
            {
                Consider(day.Add(StartTime));
                Consider(day.Add(EndTime));
            }
        }

        return soonest;

        void Consider(DateTime localInstant)
        {
            var utc = TryToUtc(localInstant, tz);
            if (utc is { } t && t > utcNow && (soonest is null || t < soonest))
                soonest = t;
        }
    }

    private static DateTimeOffset? TryToUtc(DateTime localInstant, TimeZoneInfo tz)
    {
        var unspecified = DateTime.SpecifyKind(localInstant, DateTimeKind.Unspecified);
        try
        {
            if (tz.IsInvalidTime(unspecified)) return null;
            var utc = TimeZoneInfo.ConvertTimeToUtc(unspecified, tz);
            return new DateTimeOffset(utc, TimeSpan.Zero);
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private bool DayEnabled(int dow) => Array.IndexOf(DaysOfWeek, dow) >= 0;
}
