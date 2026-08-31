namespace NetFirewall.Web.Models;

/// <summary>
/// Typed model for the <c>_TimezonePicker</c> partial — searchable IANA
/// timezone combobox. The posted value is a single IANA id (e.g.
/// <c>America/New_York</c>); the list itself comes from the browser's
/// <c>Intl.supportedValuesOf('timeZone')</c> so it matches what the host
/// can actually resolve.
/// </summary>
public sealed class TimezonePickerViewModel
{
    public required string Name { get; init; }
    public string Label { get; init; } = "Timezone";
    public string? Value { get; init; }
    public string? Help { get; init; }
    public bool Required { get; init; }
}
