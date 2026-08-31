using System.ComponentModel.DataAnnotations;
using NetFirewall.Web.Models.Firewall;

namespace NetFirewall.Tests.Firewall;

/// <summary>
/// Server-side guards on the schedule drawer form. The UI posts <c>int[]</c>
/// days and a free-text IANA timezone; both have to be rejected here so a
/// malformed POST never reaches <c>ScheduleService.Validate</c> as an
/// exception (which would toast "Save failed: …" instead of a field error).
/// </summary>
public class ScheduleFormViewModelTests
{
    private static ScheduleFormViewModel Valid(Action<ScheduleFormViewModel>? tweak = null)
    {
        var m = new ScheduleFormViewModel
        {
            Name = "WORK_HOURS",
            DaysOfWeek = new[] { 1, 2, 3, 4, 5 },
            StartTime = new TimeSpan(9, 0, 0),
            EndTime = new TimeSpan(17, 0, 0),
            Timezone = "UTC"
        };
        tweak?.Invoke(m);
        return m;
    }

    private static List<ValidationResult> Run(ScheduleFormViewModel m)
        => m.Validate(new ValidationContext(m)).ToList();

    [Fact]
    public void Validate_DefaultBusinessHours_Passes()
    {
        Assert.Empty(Run(Valid()));
    }

    [Fact]
    public void Validate_EmptyDays_FailsOnDaysOfWeek()
    {
        var results = Run(Valid(m => m.DaysOfWeek = Array.Empty<int>()));
        Assert.Contains(results, r => r.MemberNames.Contains(nameof(ScheduleFormViewModel.DaysOfWeek)));
    }

    [Fact]
    public void Validate_NullDays_FailsOnDaysOfWeek_DoesNotThrow()
    {
        var results = Run(Valid(m => m.DaysOfWeek = null!));
        Assert.Contains(results, r => r.MemberNames.Contains(nameof(ScheduleFormViewModel.DaysOfWeek)));
    }

    [Fact]
    public void Validate_OutOfRangeDay_FailsOnDaysOfWeek()
    {
        var results = Run(Valid(m => m.DaysOfWeek = new[] { 1, 7 }));
        Assert.Contains(results, r => r.MemberNames.Contains(nameof(ScheduleFormViewModel.DaysOfWeek)));
    }

    [Fact]
    public void Validate_StartNotBeforeEnd_Fails()
    {
        var results = Run(Valid(m =>
        {
            m.StartTime = new TimeSpan(17, 0, 0);
            m.EndTime = new TimeSpan(9, 0, 0);
        }));
        Assert.Contains(results, r => r.MemberNames.Contains(nameof(ScheduleFormViewModel.StartTime)));
    }

    [Fact]
    public void Validate_UnknownTimezone_FailsOnTimezone()
    {
        var results = Run(Valid(m => m.Timezone = "Mars/Olympus_Mons"));
        Assert.Contains(results, r => r.MemberNames.Contains(nameof(ScheduleFormViewModel.Timezone)));
    }

    [Fact]
    public void Validate_IanaTimezone_Passes()
    {
        Assert.Empty(Run(Valid(m => m.Timezone = "America/New_York")));
    }
}
