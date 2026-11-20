using NetFirewall.Models.Auth;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Firewall;
using NetOpenGrid.Domain.Columns;

namespace NetFirewall.Web.Grids.Firewall;

public sealed record NatRuleGridRow(
    Guid Id,
    int Priority,
    string Type,
    string? Description,
    string SourceNetwork,
    string OutInterface,
    string? OutInterfaceType,
    string? SnatAddress,
    RuleState Status)
{
    public static NatRuleGridRow From(FwNatRule n, IReadOnlyDictionary<Guid, FwInterface> ifaces)
    {
        var (name, type) = FirewallGridCells.Iface(ifaces, n.OutputInterfaceId);
        return new(n.Id, n.Priority, n.Type, n.Description, n.SourceNetwork, name, type,
            n.SnatAddress?.ToString(), FirewallGridCells.State(n.Enabled));
    }
}

/// <summary>
/// Firewall → NAT rules: SNAT / masquerade, evaluated top to bottom by priority, so the grid
/// opens sorted by priority (the old table grouped by type; "By type" keeps that view).
/// </summary>
public static class FwNatRulesGrid
{
    public const string Id = "fw-nat-rules";
    public const string DefaultQuery = "sort=priority:asc";

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<NatRuleGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("NAT rules")
            .WithEmptyMessage("No NAT rules configured. Click Add NAT rule to create one.")
            .WithRowKey(r => r.Id.ToString("D"))
            .AddView("Active", "filter=status:in:[\"Active\"]&sort=priority:asc")
            .AddView("By type", "groupby=type&sort=priority:asc")
            .AddColumn("priority", r => r.Priority, c => c
                .Header("Pri")
                .WidthCss("5rem")
                .Pinned()
                .RawCellHtml(r => GridCell.Muted(r.Priority.ToString())))
            .AddColumn("type", r => r.Type, c => c
                .Header("Type")
                .WidthCss("8rem")
                .RawCellHtml(r => GridCell.Badge(BadgeTone.Accent, r.Type.ToUpperInvariant())))
            .AddColumn("rule", r => r.Description ?? string.Empty, c => c
                .Header("Rule")
                .Searchable()
                .RawCellHtml(r => $"<div class=\"leading-tight\">{(string.IsNullOrWhiteSpace(r.Description) ? "" : $"<div class=\"font-medium\">{GridCell.Encode(r.Description)}</div>")}"
                    + $"<div class=\"mt-1\">{GridCell.Chip("src", r.SourceNetwork, r.SourceNetwork)}</div></div>"))
            .AddColumn("source", r => r.SourceNetwork, c => c
                .Header("Source")
                .Searchable()
                .Comparer(IpTextComparer.Instance)
                .HideBelow(ResponsiveBreakpoint.Lg)
                .RawCellHtml(r => GridCell.Mono(r.SourceNetwork)))
            .AddColumn("interface", r => r.OutInterface, c => c
                .Header("Out interface")
                .Searchable()
                .RawCellHtml(r => FirewallGridCells.IfaceChip(r.OutInterface, r.OutInterfaceType, "out")))
            .AddColumn("snat", r => r.SnatAddress ?? string.Empty, c => c
                .Header("SNAT")
                .Searchable()
                .Comparer(IpTextComparer.Instance)
                .HideBelow(ResponsiveBreakpoint.Md)
                .RawCellHtml(r => GridCell.Mono(r.SnatAddress)))
            .AddColumn("status", r => r.Status, c => c
                .Header("Status")
                .WidthCss("7rem")
                .RawCellHtml(r => FirewallGridCells.StateBadge(r.Status)))
            .AddColumn("actions", r => r.Id, c => c
                .Header("")
                .Sortable(false).Filterable(false).Searchable(false)
                .PinnedRight()
                .WidthCss("9rem")
                .RawCellHtml(Actions)),
        (sp, opts) => ScopedGridSource.From<IFirewallService, NatRuleGridRow>(sp, opts, async (svc, ct) =>
        {
            var rows = await svc.GetNatRulesAsync(ct);
            var ifaces = FirewallGridCells.ById(await svc.GetInterfacesAsync(ct));
            return rows.Select(r => NatRuleGridRow.From(r, ifaces)).ToArray();
        }));

    private static string Actions(NatRuleGridRow r) => GridCell.Actions(
        GridRowAction.Edit($"/Firewall/NatRules/edit/{r.Id}", "Edit NAT rule"),
        GridRowAction.Delete($"/Firewall/NatRules/delete/{r.Id}", "Delete NAT rule?",
            $"Delete {r.Type} rule for {r.SourceNetwork}?"));
}
