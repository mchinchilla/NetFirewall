using NetFirewall.Models.Auth;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetOpenGrid.Domain.Columns;

namespace NetFirewall.Web.Grids.Dhcp;

public sealed record ClassGridRow(
    Guid Id,
    int Priority,
    string Name,
    string MatchType,
    string MatchValue,
    string? NextServer,
    string? BootFilename,
    bool Enabled)
{
    public static ClassGridRow From(DhcpClass c) => new(
        c.Id, c.Priority, c.Name,
        string.IsNullOrWhiteSpace(c.MatchType) ? "other" : c.MatchType.Replace('_', ' '),
        c.MatchValue, c.NextServer?.ToString(), c.BootFilename, c.Enabled);
}

/// <summary>
/// DHCP → Client classes. The server walks enabled classes in ascending priority, so the grid
/// opens sorted by priority (evaluated top to bottom). Match type has a value checklist and is
/// the column to group by (the old table's sections).
/// </summary>
public static class DhcpClassesGrid
{
    public const string Id = "dhcp-classes";
    public const string DefaultQuery = "sort=priority:asc";

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<ClassGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("Client classes")
            .WithEmptyMessage("No classes yet. Use Add class to start steering specific client groups.")
            .WithRowKey(c => c.Id.ToString("D"))
            .AddView("Enabled", "filter=enabled:equals:true&sort=priority:asc")
            .AddView("Disabled", "filter=enabled:equals:false&sort=priority:asc")
            .AddColumn("priority", c => c.Priority, c => c
                .Header("Pri")
                .WidthCss("5rem")
                .Pinned()
                .RawCellHtml(c => $"<span class=\"font-mono text-xs tabular-nums text-surface-fg-muted\">{c.Priority}</span>"))
            .AddColumn("name", c => c.Name, c => c
                .Header("Class")
                .Searchable()
                .Pinned()
                .RawCellHtml(c => $"<span class=\"font-medium\">{GridCell.Text(c.Name)}</span>"))
            .AddColumn("matchType", c => c.MatchType, c => c
                .Header("Match")
                .Searchable()
                .WidthCss("9rem")
                .RawCellHtml(c => GridCell.Chip("match", c.MatchType)))
            .AddColumn("matchValue", c => c.MatchValue, c => c
                .Header("Value")
                .Searchable()
                .RawCellHtml(c => GridCell.Chip("val", c.MatchValue, c.MatchValue)))
            .AddColumn("nextServer", c => c.NextServer ?? string.Empty, c => c
                .Header("TFTP")
                .Comparer(IpTextComparer.Instance)
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Md)
                .RawCellHtml(c => GridCell.Chip("tftp", c.NextServer)))
            .AddColumn("bootFilename", c => c.BootFilename ?? string.Empty, c => c
                .Header("Boot file")
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Md)
                .RawCellHtml(c => GridCell.Chip("file", c.BootFilename, c.BootFilename)))
            .AddColumn("enabled", c => c.Enabled, c => c
                .Header("Status")
                .WidthCss("7rem")
                .RawCellHtml(c => GridCell.Enabled(c.Enabled)))
            .AddColumn("actions", c => c.Id, c => c
                .Header("")
                .Sortable(false).Filterable(false).Searchable(false)
                .PinnedRight()
                .WidthCss("9rem")
                .RawCellHtml(Actions)),
        (sp, opts) => ScopedGridSource.From<IDhcpAdminService, ClassGridRow>(sp, opts, async (svc, ct) =>
            (await svc.GetClassesAsync(ct)).Select(ClassGridRow.From).ToArray()));

    private static string Actions(ClassGridRow c) => GridCell.Actions(
        GridRowAction.Edit($"/Dhcp/Classes/edit/{c.Id}", $"Edit {c.Name}"),
        GridRowAction.Delete($"/Dhcp/Classes/delete/{c.Id}", "Delete class?",
            $"Delete class '{c.Name}'? Pool↔class associations are cascaded."));
}
