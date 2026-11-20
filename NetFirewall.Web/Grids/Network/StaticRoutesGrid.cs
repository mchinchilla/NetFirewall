using NetFirewall.Models.Auth;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Firewall;
using NetOpenGrid.Domain.Columns;

namespace NetFirewall.Web.Grids.Network;

/// <summary>One static route joined with its owning interface (name + LAN/WAN/VPN type).</summary>
public sealed record StaticRouteGridRow(
    Guid Id,
    string Interface,
    string? InterfaceType,
    string Destination,
    string Via,
    int Metric,
    string? Description,
    bool Enabled)
{
    public const string Direct = "direct";

    public static StaticRouteGridRow From(FwStaticRoute r, IReadOnlyDictionary<Guid, FwInterface> interfaces)
    {
        var known = interfaces.TryGetValue(r.InterfaceId, out var fi);
        return new StaticRouteGridRow(
            r.Id,
            known ? fi!.Name : "(unknown)",
            known ? fi!.Type : null,
            r.Destination,
            r.Gateway?.ToString() ?? Direct,
            r.Metric,
            r.Description,
            r.Enabled);
    }
}

/// <summary>
/// Network → Static routes. Routes are bound to interfaces; Apply regenerates the interface's
/// persistent config and live-adds the route (step-up, like Delete). The old per-interface
/// sections are the "By interface" view (group panel) now.
/// </summary>
public static class StaticRoutesGrid
{
    public const string Id = "static-routes";
    public const string DefaultQuery = "sort=interface:asc&sort=destination:asc";

    // The controller has no class-level role gate: the global authenticated policy is the only
    // gate on its read actions, so every signed-in role may read the list.
    public static void Register(NetFirewallGridBuilder grids) => grids.Add<StaticRouteGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator, UserRoles.Viewer],
        o => o
            .WithTitle("Static routes")
            .WithEmptyMessage("No static routes yet. Click Add route to create one.")
            .WithRowKey(r => r.Id.ToString("D"))
            .AddView("By interface", "groupby=interface&sort=destination:asc")
            .AddView("Active", "filter=enabled:equals:true&sort=interface:asc&sort=destination:asc")
            .AddView("Off", "filter=enabled:equals:false&sort=interface:asc&sort=destination:asc")
            .AddColumn("destination", r => r.Destination, c => c
                .Header("Destination")
                .Comparer(IpTextComparer.Instance)
                .Searchable()
                .Pinned()
                .RawCellHtml(r => GridCell.Chip("dst", r.Destination, r.Destination)))
            .AddColumn("via", r => r.Via, c => c
                .Header("Via")
                .Comparer(IpTextComparer.Instance)
                .Searchable()
                .RawCellHtml(r => GridCell.Chip("via", r.Via)))
            .AddColumn("interface", r => r.Interface, c => c
                .Header("Interface")
                .Searchable()
                .RawCellHtml(r => IfaceChip(r.Interface, r.InterfaceType)))
            .AddColumn("metric", r => r.Metric, c => c
                .Header("Metric")
                .WidthCss("6rem")
                .HideBelow(ResponsiveBreakpoint.Md)
                .RawCellHtml(r => GridCell.Mono(r.Metric.ToString())))
            .AddColumn("description", r => r.Description ?? string.Empty, c => c
                .Header("Description")
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Lg)
                .RawCellHtml(r => GridCell.Muted(r.Description)))
            .AddColumn("enabled", r => r.Enabled, c => c
                .Header("Status")
                .WidthCss("7rem")
                .RawCellHtml(r => r.Enabled ? GridCell.Badge(BadgeTone.Success, "Active") : GridCell.Badge(BadgeTone.Muted, "Off")))
            .AddColumn("actions", r => r.Id, c => c
                .Header("")
                .Sortable(false).Filterable(false).Searchable(false)
                .PinnedRight()
                .WidthCss("13rem")
                .RawCellHtml(Actions)),
        (sp, opts) => ScopedGridSource.From<IFirewallService, StaticRouteGridRow>(sp, opts, async (fw, ct) =>
        {
            var routes = await fw.GetStaticRoutesAsync(null, ct);
            var interfaces = (await fw.GetInterfacesAsync(ct)).ToDictionary(i => i.Id);
            return routes.Select(r => StaticRouteGridRow.From(r, interfaces)).ToArray();
        }));

    /// <summary>
    /// Same markup as the <c>_IfaceChip</c> partial (name + role, WAN/LAN/VPN tint).
    /// Candidate for a shared <c>GridCell.Iface</c> helper.
    /// </summary>
    private static string IfaceChip(string name, string? type)
    {
        var kind = (type ?? string.Empty).Trim().ToLowerInvariant();
        var cls = kind switch
        {
            "wan" => " iface-chip-wan",
            "lan" => " iface-chip-lan",
            "vpn" => " iface-chip-vpn",
            _ => string.Empty,
        };
        var role = string.IsNullOrWhiteSpace(type)
            ? string.Empty
            : $"<span class=\"iface-chip-role\">{GridCell.Encode(type)}</span>";
        return $"<span class=\"iface-chip{cls}\"><span class=\"iface-chip-name\">{GridCell.Encode(name)}</span>{role}</span>";
    }

    private static string Actions(StaticRouteGridRow r) => GridCell.Actions(
        new GridRowAction(GridActionKind.Post, "Apply", $"/Network/Routes/apply/{r.Id:D}")
        {
            Confirm = new GridConfirm("Apply route?",
                "Regenerates the interface config and live-adds the route via ip route.", "Apply", "warning"),
        },
        GridRowAction.Edit($"/Network/Routes/edit/{r.Id:D}", "Edit route"),
        GridRowAction.Delete($"/Network/Routes/delete/{r.Id:D}", "Delete route?",
            $"{r.Destination} via {r.Via} on {r.Interface}"));
}
