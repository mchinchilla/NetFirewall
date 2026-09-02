namespace NetFirewall.Web.Models.Shared;

/// <summary>Small labelled mono chip (src/dst/proto/port) used in rule tables.</summary>
public sealed class RuleChipViewModel
{
    public required string Label { get; init; }
    public required string Value { get; init; }
    public string? Title { get; init; }
}
