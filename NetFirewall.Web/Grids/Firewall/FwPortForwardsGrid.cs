using NetFirewall.Models.Auth;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Firewall;
using NetOpenGrid.Domain.Columns;

namespace NetFirewall.Web.Grids.Firewall;

public sealed record PortForwardGridRow(
    Guid Id,
    int Priority,
    string? Description,
    string Protocol,
    string External,
    int ExternalPortStart,
    string InternalIp,
    int InternalPort,
    string Interface,
    string? InterfaceType,
    string Sources,
    RuleState Status)
{
    public string Title => string.IsNullOrWhiteSpace(Description) ? $"{Protocol.ToUpperInvariant()} / {External}" : Description;
    public string Mapping => $":{External} → {InternalIp}:{InternalPort}";

    public static PortForwardGridRow From(FwPortForward pf, IReadOnlyDictionary<Guid, FwInterface> ifaces)
    {
        var ext = pf.ExternalPortEnd is { } end && end > pf.ExternalPortStart
            ? $"{pf.ExternalPortStart}-{end}"
            : pf.ExternalPortStart.ToString();
        var (name, type) = FirewallGridCells.Iface(ifaces, pf.InterfaceId);
        var sources = pf.SourceAddresses is { Length: > 0 } ? string.Join(", ", pf.SourceAddresses) : "any";
        return new(pf.Id, pf.Priority, pf.Description, pf.Protocol, ext, pf.ExternalPortStart,
            pf.InternalIp.ToString(), pf.InternalPort, name, type, sources, FirewallGridCells.State(pf.Enabled));
    }
}

/// <summary>Firewall → Port forwards: DNAT rules, edited in the host drawer.</summary>
public static class FwPortForwardsGrid
{
    public const string Id = "fw-port-forwards";
    public const string DefaultQuery = "sort=priority:asc";

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<PortForwardGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("Port forwards")
            .WithEmptyMessage("No port forwards configured. Click Add forward to create one.")
            .WithRowKey(r => r.Id.ToString("D"))
            .AddView("Active", "filter=status:in:[\"Active\"]&sort=priority:asc")
            .AddView("Off", "filter=status:in:[\"Off\"]&sort=priority:asc")
            .AddView("By interface", "groupby=interface&sort=priority:asc")
            .AddColumn("priority", r => r.Priority, c => c
                .Header("Pri")
                .WidthCss("5rem")
                .RawCellHtml(r => GridCell.Muted(r.Priority.ToString())))
            .AddColumn("forward", r => r.Title, c => c
                .Header("Forward")
                .Searchable()
                .Pinned()
                .RawCellHtml(r => $"<div class=\"leading-tight\"><div class=\"font-medium\">{GridCell.Encode(r.Title)}</div>"
                    + $"<div class=\"mt-1\">{GridCell.Wrap(GridCell.Chip("proto", r.Protocol), GridCell.Chip("ext", r.External))}</div></div>"))
            .AddColumn("protocol", r => r.Protocol, c => c
                .Header("Protocol")
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Lg)
                .RawCellHtml(r => GridCell.Mono(r.Protocol)))
            .AddColumn("mapping", r => r.Mapping, c => c
                .Header("External → Internal")
                .Searchable()
                .RawCellHtml(r => GridCell.Mono(r.Mapping)))
            .AddColumn("interface", r => r.Interface, c => c
                .Header("Interface")
                .Searchable()
                .RawCellHtml(r => FirewallGridCells.IfaceChip(r.Interface, r.InterfaceType)))
            .AddColumn("sources", r => r.Sources, c => c
                .Header("Sources")
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Md)
                .RawCellHtml(r => GridCell.Chip("src", r.Sources, r.Sources)))
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
        (sp, opts) => ScopedGridSource.From<IFirewallService, PortForwardGridRow>(sp, opts, async (svc, ct) =>
        {
            var rows = await svc.GetPortForwardsAsync(ct);
            var ifaces = FirewallGridCells.ById(await svc.GetInterfacesAsync(ct));
            return rows.Select(r => PortForwardGridRow.From(r, ifaces)).ToArray();
        }));

    private static string Actions(PortForwardGridRow r) => GridCell.Actions(
        GridRowAction.Edit($"/Firewall/PortForwards/edit/{r.Id}", "Edit port forward"),
        GridRowAction.Delete($"/Firewall/PortForwards/delete/{r.Id}", "Delete forward?",
            $"Delete forward {r.Protocol}/{r.External} → {r.InternalIp}:{r.InternalPort}?"));
}
