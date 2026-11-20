using System.Globalization;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Dhcp;
using NetOpenGrid.Domain.Columns;

namespace NetFirewall.Web.Grids.Dhcp;

public sealed record LeaseHistoryGridRow(long Id, string Ip, string Mac, string? Hostname, DateTime FirstSeen, DateTime LastSeen, bool Current)
{
    public static LeaseHistoryGridRow From(DhcpLeaseHistoryRow r) =>
        new(r.Id, r.Ip.ToString(), r.Mac, r.Hostname, r.FirstSeen, r.LastSeen, r.Current);
}

/// <summary>DHCP → Lease history: which device held which address, when. Search an IP or a MAC.</summary>
public static class DhcpLeaseHistoryGrid
{
    public const string Id = "dhcp-lease-history";
    public const string DefaultQuery = "sort=lastSeen:desc";

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<LeaseHistoryGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("Lease history")
            .WithEmptyMessage("No history yet — it starts with the next lease the DHCP server hands out.")
            .WithRowKey(r => r.Id.ToString(CultureInfo.InvariantCulture))
            .AddView("Current", "filter=current:equals:true&sort=lastSeen:desc")
            .AddColumn("ip", r => r.Ip, c => c
                .Header("Address")
                .Comparer(IpTextComparer.Instance)
                .Searchable()
                .Pinned()
                .RawCellHtml(r => GridCell.Chip("ip", r.Ip)))
            .AddColumn("mac", r => r.Mac, c => c
                .Header("Device (MAC)")
                .Searchable()
                .RawCellHtml(r => GridCell.Mono(r.Mac)))
            .AddColumn("hostname", r => r.Hostname ?? string.Empty, c => c
                .Header("Host name")
                .Searchable()
                .RawCellHtml(r => GridCell.Text(r.Hostname ?? "—")))
            .AddColumn("firstSeen", r => r.FirstSeen, c => c
                .Header("From")
                .RawCellHtml(r => GridCell.Mono(r.FirstSeen.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture))))
            .AddColumn("lastSeen", r => r.LastSeen, c => c
                .Header("Last seen")
                .RawCellHtml(r => GridCell.Mono(r.LastSeen.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture))))
            .AddColumn("current", r => r.Current, c => c
                .Header("Status")
                .WidthCss("7rem")
                .HideBelow(ResponsiveBreakpoint.Md)
                .RawCellHtml(r => r.Current ? GridCell.Badge(BadgeTone.Success, "Current") : GridCell.Badge(BadgeTone.Muted, "Ended"))),
        (sp, opts) => ScopedGridSource.From<IDhcpLeaseHistoryService, LeaseHistoryGridRow>(sp, opts,
            async (svc, ct) => (await svc.RecentAsync(ct: ct)).Select(LeaseHistoryGridRow.From).ToArray()));
}
