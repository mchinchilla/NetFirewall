namespace NetFirewall.Web.Models;

/// <summary>
/// Typed model for the reusable <c>_FormField</c> partial.
/// Centralises label / control / inline error rendering so every form in
/// the app looks identical and honors project rule #4 (dual validation —
/// the same model carries the server-side error message for inline display).
/// </summary>
public sealed class FormFieldViewModel
{
    public required string Name { get; init; }
    public required string Label { get; init; }
    public FormFieldKind Kind { get; init; } = FormFieldKind.Text;
    public string? Value { get; init; }
    public string? Placeholder { get; init; }
    public string? Help { get; init; }
    public string? Error { get; init; }
    public bool Required { get; init; }
    public bool Disabled { get; init; }
    public string? AlpineModel { get; init; }   // x-model="..."
    public string? AlpineExtra { get; init; }   // arbitrary x-* attrs (e.g. ":disabled='...'")
    public string? Pattern { get; init; }       // HTML5 pattern attribute (client-side validation)
    public int? MinLength { get; init; }
    public int? MaxLength { get; init; }
    public string? Min { get; init; }           // for number/date
    public string? Max { get; init; }
    public IReadOnlyList<SelectOption>? Options { get; init; } // for Select kind

    public sealed record SelectOption(string Value, string Label, bool Selected = false);
}

public enum FormFieldKind
{
    Text,
    Email,
    Number,
    Password,
    Select,
    Checkbox,
    Textarea
}
