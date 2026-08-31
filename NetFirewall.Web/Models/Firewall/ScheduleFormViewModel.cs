using System.ComponentModel.DataAnnotations;

namespace NetFirewall.Web.Models.Firewall;

public sealed class ScheduleFormViewModel : IValidatableObject
{
    public Guid? Id { get; set; }

    [Required, StringLength(80)]
    public string Name { get; set; } = string.Empty;

    [StringLength(500)]
    public string? Description { get; set; }

    /// <summary>0=Sun..6=Sat — multi-select on the form.</summary>
    public int[] DaysOfWeek { get; set; } = new[] { 1, 2, 3, 4, 5 }; // weekdays default

    [Required]
    public TimeSpan StartTime { get; set; } = new(9, 0, 0);

    [Required]
    public TimeSpan EndTime { get; set; } = new(17, 0, 0);

    [Required, StringLength(64)]
    public string Timezone { get; set; } = "UTC";

    public bool Enabled { get; set; } = true;

    public IEnumerable<ValidationResult> Validate(ValidationContext context)
    {
        if (StartTime == EndTime)
            yield return new ValidationResult(
                "Start and end time cannot be the same. A window that starts after it ends wraps midnight (e.g. 22:00–06:00).",
                new[] { nameof(StartTime), nameof(EndTime) });
        if (DaysOfWeek is not { Length: > 0 })
            yield return new ValidationResult("Pick at least one day.", new[] { nameof(DaysOfWeek) });
        else if (DaysOfWeek.Any(d => d < 0 || d > 6))
            yield return new ValidationResult("Days of week must be 0-6 (Sun-Sat).",
                new[] { nameof(DaysOfWeek) });

        if (string.IsNullOrWhiteSpace(Timezone))
            yield return new ValidationResult("Timezone is required.", new[] { nameof(Timezone) });
        else if (!TryResolveTimezone(Timezone.Trim()))
            yield return new ValidationResult(
                $"Unknown timezone '{Timezone}'. Use an IANA name like America/New_York.",
                new[] { nameof(Timezone) });
    }

    private static bool TryResolveTimezone(string id)
    {
        try { TimeZoneInfo.FindSystemTimeZoneById(id); return true; }
        catch (TimeZoneNotFoundException) { return false; }
        catch (InvalidTimeZoneException) { return false; }
    }
}
