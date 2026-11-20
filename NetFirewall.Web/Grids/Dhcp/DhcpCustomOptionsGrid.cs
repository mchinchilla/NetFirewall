using NetFirewall.Models.Auth;
using NetFirewall.Services.Dhcp;
using NetOpenGrid.Domain.Columns;

namespace NetFirewall.Web.Grids.Dhcp;

/// <summary>DHCP → Custom options: one row per option per scope, grouped by who receives it.</summary>
public static class DhcpCustomOptionsGrid
{
    public const string Id = "dhcp-custom-options";
    public const string DefaultQuery = "sort=code:asc";

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<DhcpCustomOptionRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("Custom options")
            .WithEmptyMessage("No custom options yet. Add one to hand phones, access points or other devices a setting the standard fields don't cover.")
            .WithRowKey(r => r.Id.ToString("D"))
            .AddView("By scope", "groupby=scope&sort=code:asc")
            .AddColumn("code", r => (int)r.Code, c => c
                .Header("Option")
                .WidthCss("6rem")
                .Pinned()
                .RawCellHtml(r => $"<span class=\"font-mono tabular-nums font-medium\">{r.Code}</span>"))
            .AddColumn("name", r => r.Name ?? string.Empty, c => c
                .Header("Name")
                .Searchable()
                .RawCellHtml(r => GridCell.Text(r.Name ?? "—")))
            .AddColumn("scope", r => r.ScopeLabel, c => c
                .Header("Applies to")
                .Searchable()
                .RawCellHtml(r => GridCell.Chip(r.ScopeType, r.ScopeLabel)))
            .AddColumn("value", r => r.ValueText, c => c
                .Header("Value")
                .Searchable()
                .RawCellHtml(r => GridCell.Mono(r.ValueText)))
            .AddColumn("format", r => r.Format ?? "hex", c => c
                .Header("Format")
                .WidthCss("7rem")
                .HideBelow(ResponsiveBreakpoint.Md)
                .RawCellHtml(r => GridCell.Muted(r.Format ?? "hex")))
            .AddColumn("actions", r => r.Id, c => c
                .Header("")
                .Sortable(false).Filterable(false).Searchable(false)
                .PinnedRight()
                .WidthCss("9rem")
                .RawCellHtml(r => GridCell.Actions(
                    GridRowAction.Edit($"/Dhcp/Options/edit/{r.Id}", $"Edit option {r.Code}"),
                    GridRowAction.Delete($"/Dhcp/Options/delete/{r.Id}", "Delete option?",
                        $"Stop sending option {r.Code} to {r.ScopeLabel}? Clients drop it at their next renewal.")))),
        (sp, opts) => ScopedGridSource.From<IDhcpCustomOptionService, DhcpCustomOptionRow>(sp, opts,
            async (svc, ct) => (await svc.ListAsync(ct)).ToArray()));
}
