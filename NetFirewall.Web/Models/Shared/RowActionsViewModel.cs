namespace NetFirewall.Web.Models.Shared;

/// <summary>Edit + confirm-delete pair used by every firewall list row.</summary>
public sealed class RowActionsViewModel
{
    public required string EditUrl { get; init; }
    public string EditDrawerTitle { get; init; } = "Edit";
    public required string DeleteUrl { get; init; }
    public string DeleteDialogTitle { get; init; } = "Delete?";
    public required string DeleteMessage { get; init; }
    public string DeleteConfirmLabel { get; init; } = "Delete";
}
