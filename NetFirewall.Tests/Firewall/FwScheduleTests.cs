using NetFirewall.Models.Firewall;
using Xunit;

namespace NetFirewall.Tests.Firewall;

/// <summary>
/// Time-window logic for <see cref="FwSchedule.IsActiveAt"/>. The watcher
/// service in the daemon polls this on every tick; getting it wrong means
/// rules turn on/off at the wrong moment, so we want explicit boundary tests.
/// </summary>
public class FwScheduleTests
{
    private static FwSchedule Make(
        TimeSpan start, TimeSpan end,
        int[]? days = null,
        string tz = "UTC",
        bool enabled = true)
        => new()
        {
            Id = Guid.NewGuid(),
            Name = "test",
            DaysOfWeek = days ?? new[] { 0, 1, 2, 3, 4, 5, 6 },
            StartTime = start,
            EndTime = end,
            Timezone = tz,
            Enabled = enabled
        };

    // ── enabled flag ───────────────────────────────────────────────────

    [Fact]
    public void Disabled_AlwaysReturnsFalse_EvenInsideWindow()
    {
        var s = Make(TimeSpan.FromHours(0), TimeSpan.FromHours(23), enabled: false);
        // Pick noon UTC any day — would otherwise match.
        Assert.False(s.IsActiveAt(new DateTimeOffset(2026, 4, 27, 12, 0, 0, TimeSpan.Zero)));
    }

    // ── day-of-week filter ─────────────────────────────────────────────

    [Fact]
    public void DayOfWeekFilter_ExcludesDaysNotInList()
    {
        // Only weekdays (Mon..Fri = 1..5)
        var s = Make(TimeSpan.FromHours(0), TimeSpan.FromHours(23), days: new[] { 1, 2, 3, 4, 5 });

        // 2026-04-26 is Sunday (dow=0)
        var sundayNoon = new DateTimeOffset(2026, 4, 26, 12, 0, 0, TimeSpan.Zero);
        Assert.False(s.IsActiveAt(sundayNoon));

        // 2026-04-27 is Monday (dow=1)
        var mondayNoon = new DateTimeOffset(2026, 4, 27, 12, 0, 0, TimeSpan.Zero);
        Assert.True(s.IsActiveAt(mondayNoon));
    }

    [Theory]
    [InlineData(0)]  // Sun
    [InlineData(6)]  // Sat
    public void DayOfWeekFilter_AllowsBoundaryDays(int dow)
    {
        var s = Make(TimeSpan.Zero, TimeSpan.FromHours(23), days: new[] { dow });

        // Pick the right calendar day: 2026-04-26 (Sun) and 2026-05-02 (Sat)
        var date = dow == 0
            ? new DateTimeOffset(2026, 4, 26, 12, 0, 0, TimeSpan.Zero)
            : new DateTimeOffset(2026, 5, 2, 12, 0, 0, TimeSpan.Zero);
        Assert.True(s.IsActiveAt(date));
    }

    // ── time window inclusivity ────────────────────────────────────────

    [Fact]
    public void TimeWindow_StartIsInclusive()
    {
        var s = Make(TimeSpan.FromHours(9), TimeSpan.FromHours(17));
        var atStart = new DateTimeOffset(2026, 4, 27, 9, 0, 0, TimeSpan.Zero);
        Assert.True(s.IsActiveAt(atStart));
    }

    [Fact]
    public void TimeWindow_EndIsExclusive()
    {
        var s = Make(TimeSpan.FromHours(9), TimeSpan.FromHours(17));
        var atEnd = new DateTimeOffset(2026, 4, 27, 17, 0, 0, TimeSpan.Zero);
        Assert.False(s.IsActiveAt(atEnd));
    }

    [Fact]
    public void TimeWindow_JustBeforeEndIsActive()
    {
        var s = Make(TimeSpan.FromHours(9), TimeSpan.FromHours(17));
        var almostEnd = new DateTimeOffset(2026, 4, 27, 16, 59, 59, TimeSpan.Zero);
        Assert.True(s.IsActiveAt(almostEnd));
    }

    [Fact]
    public void TimeWindow_OutsideReturnsFalse()
    {
        var s = Make(TimeSpan.FromHours(9), TimeSpan.FromHours(17));
        Assert.False(s.IsActiveAt(new DateTimeOffset(2026, 4, 27, 8, 59, 0, TimeSpan.Zero)));
        Assert.False(s.IsActiveAt(new DateTimeOffset(2026, 4, 27, 18, 0, 0, TimeSpan.Zero)));
    }

    // ── timezone conversion ────────────────────────────────────────────

    [Fact]
    public void Timezone_LocalWindowAppliesInThatZone_NotUtc()
    {
        // Window: 14:00–15:00 in America/New_York. EDT = UTC-4 in late April.
        // 14:00 EDT = 18:00 UTC; 15:00 EDT = 19:00 UTC.
        var s = Make(TimeSpan.FromHours(14), TimeSpan.FromHours(15), tz: "America/New_York");

        // 18:30 UTC on 2026-04-27 → 14:30 EDT → inside window.
        Assert.True(s.IsActiveAt(new DateTimeOffset(2026, 4, 27, 18, 30, 0, TimeSpan.Zero)));

        // 13:30 UTC → 09:30 EDT → outside.
        Assert.False(s.IsActiveAt(new DateTimeOffset(2026, 4, 27, 13, 30, 0, TimeSpan.Zero)));
    }

    [Fact]
    public void Timezone_DayOfWeekUsesLocalTime_NotUtc()
    {
        // Asia/Tokyo is UTC+9. At 23:00 UTC Sunday (dow=0), local time is
        // 08:00 Monday (dow=1). A Monday-only schedule should be active then.
        var s = Make(
            TimeSpan.FromHours(7), TimeSpan.FromHours(9),
            days: new[] { 1 },
            tz: "Asia/Tokyo");

        // 2026-04-26 is Sunday in UTC. 23:00 UTC = 08:00 Monday in Tokyo.
        var sundayNightUtc = new DateTimeOffset(2026, 4, 26, 23, 0, 0, TimeSpan.Zero);
        Assert.True(s.IsActiveAt(sundayNightUtc));
    }

    [Fact]
    public void Timezone_InvalidIanaName_FallsBackToUtc_NoThrow()
    {
        var s = Make(TimeSpan.FromHours(9), TimeSpan.FromHours(17), tz: "Mars/Olympus_Mons");

        // Should silently treat as UTC. 12:00 UTC inside 09:00–17:00 → true.
        Assert.True(s.IsActiveAt(new DateTimeOffset(2026, 4, 27, 12, 0, 0, TimeSpan.Zero)));
    }

    // ── invariants ─────────────────────────────────────────────────────

    [Fact]
    public void DefaultSchedule_IsAlwaysActive_AcrossArbitraryMoments()
    {
        // Defaults: all days, 00:00–23:59, enabled, UTC.
        var s = new FwSchedule { Name = "default" };

        Assert.True(s.IsActiveAt(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero)));     // Thu, midnight
        Assert.True(s.IsActiveAt(new DateTimeOffset(2026, 4, 27, 12, 0, 0, TimeSpan.Zero)));   // Mon, noon
        Assert.True(s.IsActiveAt(new DateTimeOffset(2026, 12, 31, 23, 58, 0, TimeSpan.Zero))); // Thu, just before end-of-day
    }

    [Fact]
    public void EmptyDaysOfWeek_NeverActive()
    {
        var s = Make(TimeSpan.Zero, TimeSpan.FromHours(23), days: Array.Empty<int>());
        Assert.False(s.IsActiveAt(new DateTimeOffset(2026, 4, 27, 12, 0, 0, TimeSpan.Zero)));
    }
}
