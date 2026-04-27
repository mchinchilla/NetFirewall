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
        if (StartTime >= EndTime)
            yield return new ValidationResult("Start time must be earlier than end time.",
                new[] { nameof(StartTime), nameof(EndTime) });
        if (DaysOfWeek.Length == 0)
            yield return new ValidationResult("Pick at least one day.", new[] { nameof(DaysOfWeek) });
    }
}
