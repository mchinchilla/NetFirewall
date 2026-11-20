using NetFirewall.Models.Auth;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetOpenGrid.Domain.Columns;

namespace NetFirewall.Web.Grids.Dhcp;

/// <summary>
/// One failover peer as the grid sees it. Only persisted config: the runtime fields of
/// <see cref="FailoverPeer"/> (CurrentState, IsConnected…) are never loaded from the DB, and the
/// shared secret stays out of the row (cells, search and export).
/// </summary>
public sealed record FailoverGridRow(
    Guid Id,
    string Name,
    string Role,
    string PeerAddress,
    int PeerPort,
    string? LocalAddress,
    int LocalPort,
    int Split,
    int McltSeconds,
    bool Enabled)
{
    public static FailoverGridRow From(FailoverPeer p) => new(
        p.Id, p.Name, p.Role, p.PeerAddress.ToString(), p.PeerPort,
        p.LocalAddress?.ToString(), p.LocalPort, p.Split, p.Mclt, p.Enabled);
}

/// <summary>
/// DHCP → Failover peers. The live state stays in the page's "Current state" card; the grid
/// lists the configured relationships and expands each into its protocol tuning
/// (<c>/Dhcp/Failover/detail</c>).
/// </summary>
public static class DhcpFailoverGrid
{
    public const string Id = "dhcp-failover";
    public const string DefaultQuery = "sort=name:asc";

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<FailoverGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("Failover peers")
            .WithEmptyMessage("No failover peers configured. Use Add peer to enable HA — until then the server runs standalone.")
            .WithRowKey(p => p.Id.ToString("D"))
            .WithRowDetail(p => $"/Dhcp/Failover/detail/{p.Id:D}")
            .AddView("Enabled", "filter=enabled:equals:true&sort=name:asc")
            .AddView("Disabled", "filter=enabled:equals:false&sort=name:asc")
            .AddColumn("name", p => p.Name, c => c
                .Header("Peer")
                .Searchable()
                .Pinned()
                .RawCellHtml(p => $"<span class=\"font-medium\">{GridCell.Text(p.Name)}</span>"))
            .AddColumn("peerAddress", p => p.PeerAddress, c => c
                .Header("Peer address")
                .Comparer(IpTextComparer.Instance)
                .Searchable()
                .RawCellHtml(p => GridCell.Chip("peer", $"{p.PeerAddress}:{p.PeerPort}")))
            .AddColumn("role", p => p.Role, c => c
                .Header("Role")
                .WidthCss("8rem")
                .RawCellHtml(p => $"<span class=\"badge badge-accent uppercase tracking-wide\">{GridCell.Encode(p.Role)}</span>"))
            .AddColumn("localAddress", p => p.LocalAddress ?? string.Empty, c => c
                .Header("Local")
                .Comparer(IpTextComparer.Instance)
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Lg)
                .RawCellHtml(p => p.LocalAddress is null
                    ? GridCell.Muted($"any:{p.LocalPort}")
                    : GridCell.Chip("local", $"{p.LocalAddress}:{p.LocalPort}")))
            .AddColumn("split", p => p.Split, c => c
                .Header("Split")
                .WidthCss("6rem")
                .HideBelow(ResponsiveBreakpoint.Md)
                .RawCellHtml(p => GridCell.Chip("split", p.Split.ToString(System.Globalization.CultureInfo.InvariantCulture))))
            .AddColumn("mclt", p => p.McltSeconds, c => c
                .Header("MCLT")
                .WidthCss("6rem")
                .HideBelow(ResponsiveBreakpoint.Md)
                .RawCellHtml(p => GridCell.Chip("mclt", $"{p.McltSeconds / 60}m")))
            .AddColumn("enabled", p => p.Enabled, c => c
                .Header("Status")
                .WidthCss("7rem")
                .RawCellHtml(p => GridCell.Enabled(p.Enabled)))
            .AddColumn("actions", p => p.Id, c => c
                .Header("")
                .Sortable(false).Filterable(false).Searchable(false)
                .PinnedRight()
                .WidthCss("9rem")
                .RawCellHtml(Actions)),
        (sp, opts) => ScopedGridSource.From<IDhcpAdminService, FailoverGridRow>(sp, opts, async (svc, ct) =>
            (await svc.GetFailoverPeersAsync(ct)).Select(FailoverGridRow.From).ToArray()));

    private static string Actions(FailoverGridRow p) => GridCell.Actions(
        GridRowAction.Edit($"/Dhcp/Failover/edit/{p.Id}", $"Edit {p.Name}"),
        GridRowAction.Delete($"/Dhcp/Failover/delete/{p.Id}", "Delete peer?",
            $"Delete failover peer '{p.Name}'? The DHCP server will fall back to standalone on next start."));
}
