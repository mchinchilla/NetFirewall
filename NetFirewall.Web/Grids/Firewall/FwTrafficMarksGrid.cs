using NetFirewall.Models.Auth;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Firewall;
using NetOpenGrid.Domain.Columns;

namespace NetFirewall.Web.Grids.Firewall;

/// <summary>What a mark is for: it carries a route table (policy routing) or it only classifies (QoS / matching).</summary>
public enum MarkUse { PolicyRouting, Classification }

public sealed record TrafficMarkGridRow(Guid Id, string Name, string? Description, int Value, string? RouteTable, MarkUse Use)
{
    public string Hex => $"0x{Value:X}";

    public static TrafficMarkGridRow From(FwTrafficMark m) => new(
        m.Id, m.Name, m.Description, m.MarkValue, string.IsNullOrWhiteSpace(m.RouteTable) ? null : m.RouteTable,
        string.IsNullOrWhiteSpace(m.RouteTable) ? MarkUse.Classification : MarkUse.PolicyRouting);
}

/// <summary>Firewall → Traffic marks: named fwmark values used by mangle rules, QoS classes and policy routing.</summary>
public static class FwTrafficMarksGrid
{
    public const string Id = "fw-traffic-marks";
    public const string DefaultQuery = "sort=value:asc";

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<TrafficMarkGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("Traffic marks")
            .WithEmptyMessage("No marks defined yet. Click Add mark to create one.")
            .WithRowKey(r => r.Id.ToString("D"))
            .AddView("Policy routing", "filter=use:in:[\"PolicyRouting\"]&sort=value:asc")
            .AddView("Classification", "filter=use:in:[\"Classification\"]&sort=value:asc")
            .AddView("By use", "groupby=use&sort=value:asc")
            .AddColumn("name", r => r.Name, c => c
                .Header("Name")
                .SearchMatch((r, q) => q is null
                    || r.Name.Contains(q, StringComparison.OrdinalIgnoreCase)
                    || (r.Description?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false))
                .Pinned()
                .RawCellHtml(r => GridCell.TwoLine(r.Name, r.Description)))
            .AddColumn("value", r => r.Value, c => c
                .Header("Mark")
                .SearchMatch((r, q) => q is null
                    || r.Value.ToString().Contains(q, StringComparison.OrdinalIgnoreCase)
                    || r.Hex.Contains(q, StringComparison.OrdinalIgnoreCase))
                .RawCellHtml(r => GridCell.Wrap(GridCell.Chip("dec", r.Value.ToString()), GridCell.Chip("hex", r.Hex))))
            .AddColumn("routeTable", r => r.RouteTable ?? string.Empty, c => c
                .Header("Route table")
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Md)
                .RawCellHtml(r => r.RouteTable is null ? GridCell.Empty : GridCell.Chip("table", r.RouteTable)))
            .AddColumn("use", r => r.Use, c => c
                .Header("Use")
                .WidthCss("9rem")
                .HideBelow(ResponsiveBreakpoint.Lg)
                .RawCellHtml(r => r.Use == MarkUse.PolicyRouting
                    ? GridCell.Badge(BadgeTone.Accent, "Policy routing")
                    : GridCell.Badge(BadgeTone.Muted, "Classification")))
            .AddColumn("actions", r => r.Id, c => c
                .Header("")
                .Sortable(false).Filterable(false).Searchable(false)
                .PinnedRight()
                .WidthCss("9rem")
                .RawCellHtml(Actions)),
        (sp, opts) => ScopedGridSource.From<IFirewallService, TrafficMarkGridRow>(sp, opts, async (svc, ct) =>
            (await svc.GetTrafficMarksAsync(ct)).Select(TrafficMarkGridRow.From).ToArray()));

    private static string Actions(TrafficMarkGridRow r) => GridCell.Actions(
        GridRowAction.Edit($"/Firewall/TrafficMarks/edit/{r.Id}", "Edit mark"),
        GridRowAction.Delete($"/Firewall/TrafficMarks/delete/{r.Id}", "Delete mark?",
            $"Delete mark '{r.Name}' ({r.Hex})? Mangle rules and QoS classes referencing it will lose the binding."));
}
