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

    /// <summary>True iff "now" (in this schedule's timezone) falls inside the window AND today's dow is enabled.</summary>
    public bool IsActiveAt(DateTimeOffset utcNow)
    {
        if (!Enabled) return false;
        TimeZoneInfo tz;
        try { tz = TimeZoneInfo.FindSystemTimeZoneById(Timezone); }
        catch { tz = TimeZoneInfo.Utc; }

        var local = TimeZoneInfo.ConvertTimeFromUtc(utcNow.UtcDateTime, tz);
        var dow = (int)local.DayOfWeek; // matches Postgres dow (0=Sun..6=Sat)
        if (Array.IndexOf(DaysOfWeek, dow) < 0) return false;

        var t = local.TimeOfDay;
        return t >= StartTime && t < EndTime;
    }
}
