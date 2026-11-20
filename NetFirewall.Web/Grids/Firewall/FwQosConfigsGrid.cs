using NetFirewall.Models.Auth;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Firewall;

namespace NetFirewall.Web.Grids.Firewall;

public sealed record QosConfigGridRow(Guid Id, string Interface, string? InterfaceType, int BandwidthMbps, RuleState Status)
{
    public static QosConfigGridRow From(FwQosConfig c, IReadOnlyDictionary<Guid, FwInterface> ifaces)
    {
        var (name, type) = FirewallGridCells.Iface(ifaces, c.InterfaceId);
        return new(c.Id, name, type, c.TotalBandwidthMbps, FirewallGridCells.State(c.Enabled));
    }
}

/// <summary>
/// Firewall → QoS: one HTB shaper per interface. "Classes" navigates the whole page (not the
/// grid frame) to the config's classes; Edit / Delete go through the host drawer and confirm.
/// </summary>
public static class FwQosConfigsGrid
{
    public const string Id = "fw-qos-configs";
    public const string DefaultQuery = "sort=interface:asc";

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<QosConfigGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("QoS configurations")
            .WithEmptyMessage("No QoS configurations yet. Click Add QoS config to create one.")
            .WithRowKey(r => r.Id.ToString("D"))
            .AddView("Active", "filter=status:in:[\"Active\"]&sort=interface:asc")
            .AddColumn("interface", r => r.Interface, c => c
                .Header("Interface")
                .Searchable()
                .Pinned()
                .RawCellHtml(r => FirewallGridCells.IfaceChip(r.Interface, r.InterfaceType)))
            .AddColumn("bandwidth", r => r.BandwidthMbps, c => c
                .Header("Bandwidth")
                .SearchMatch((r, q) => q is null || $"{r.BandwidthMbps} Mbps".Contains(q, StringComparison.OrdinalIgnoreCase))
                .RawCellHtml(r => GridCell.Chip("total", $"{r.BandwidthMbps} Mbps")))
            .AddColumn("status", r => r.Status, c => c
                .Header("Status")
                .WidthCss("7rem")
                .RawCellHtml(r => FirewallGridCells.StateBadge(r.Status)))
            .AddColumn("actions", r => r.Id, c => c
                .Header("")
                .Sortable(false).Filterable(false).Searchable(false)
                .PinnedRight()
                .WidthCss("13rem")
                .RawCellHtml(Actions)),
        (sp, opts) => ScopedGridSource.From<IFirewallService, QosConfigGridRow>(sp, opts, async (svc, ct) =>
        {
            var rows = await svc.GetQosConfigsAsync(ct);
            var ifaces = FirewallGridCells.ById(await svc.GetInterfacesAsync(ct));
            return rows.Select(r => QosConfigGridRow.From(r, ifaces)).ToArray();
        }));

    private static string Actions(QosConfigGridRow r) => FirewallGridCells.ActionsWithLink(
        $"/Firewall/Qos/{r.Id}/Classes", "Classes",
        GridRowAction.Edit($"/Firewall/Qos/edit/{r.Id}", "Edit QoS config"),
        GridRowAction.Delete($"/Firewall/Qos/delete/{r.Id}", "Delete QoS config?",
            $"Delete QoS config for '{r.Interface}'? All child classes will also be deleted (cascade)."));
}
