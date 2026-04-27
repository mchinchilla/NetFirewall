namespace NetFirewall.Web.Models;

/// <summary>
/// Typed model for the <c>_AddressPicker</c> partial — tag input with
/// network-object autocomplete used by every firewall rule editor's
/// source/destination fields.
/// </summary>
public sealed class AddressPickerViewModel
{
    public required string Name { get; init; }
    public required string Label { get; init; }
    public string? Value { get; init; }       // comma-separated existing tags
    public string? Placeholder { get; init; }
    public string? Help { get; init; }
    public bool Required { get; init; }
}
