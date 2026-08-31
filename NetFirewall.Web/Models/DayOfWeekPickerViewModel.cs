namespace NetFirewall.Web.Models;

/// <summary>
/// Typed model for the <c>_DayOfWeekPicker</c> partial. Posts the same
/// <c>int[]</c> (0=Sun .. 6=Sat) the schedule form already binds.
/// </summary>
public sealed class DayOfWeekPickerViewModel
{
    public required string Name { get; init; }
    public string Label { get; init; } = "Days of week";
    public int[] Selected { get; init; } = Array.Empty<int>();
    public bool Required { get; init; }
}
