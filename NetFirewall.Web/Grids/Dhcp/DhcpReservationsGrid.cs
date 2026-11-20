using NetFirewall.Models.Auth;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;

namespace NetFirewall.Web.Grids.Dhcp;

public sealed record ReservationGridRow(Guid Id, string Mac, string Ip, string? Description)
{
    public static ReservationGridRow From(DhcpMacReservation r) =>
        new(r.Id, LeaseGridRow.MacText(r.MacAddress.ToString()), r.ReservedIp.ToString(), r.Description);
}

/// <summary>DHCP → Reservations: static MAC → IP bindings, edited in the host drawer.</summary>
public static class DhcpReservationsGrid
{
    public const string Id = "dhcp-reservations";

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<ReservationGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("Reservations")
            .WithEmptyMessage("No reservations yet. Use Add reservation to bind a MAC address to an IP.")
            .WithRowKey(r => r.Id.ToString("D"))
            .AddColumn("ip", r => r.Ip, c => c
                .Header("Reserved IP")
                .Comparer(IpTextComparer.Instance)
                .Searchable()
                .Pinned()
                .RawCellHtml(r => GridCell.Chip("ip", r.Ip)))
            .AddColumn("mac", r => r.Mac, c => c
                .Header("MAC")
                .Searchable()
                .RawCellHtml(r => GridCell.Chip("mac", r.Mac)))
            .AddColumn("description", r => r.Description ?? string.Empty, c => c
                .Header("Description")
                .Searchable()
                .RawCellHtml(r => GridCell.Muted(r.Description)))
            .AddColumn("actions", r => r.Id, c => c
                .Header("")
                .Sortable(false).Filterable(false).Searchable(false)
                .PinnedRight()
                .WidthCss("13rem")
                .RawCellHtml(Actions)),
        (sp, opts) => ScopedGridSource.From<IDhcpAdminService, ReservationGridRow>(sp, opts, async (svc, ct) =>
            (await svc.GetReservationsAsync(ct: ct)).Select(ReservationGridRow.From).ToArray()));

    private static string Actions(ReservationGridRow r) => GridCell.Actions(
        new GridRowAction(GridActionKind.Post, "Wake", "/Network/WakeOnLan/wake")
        {
            Values = new Dictionary<string, string> { ["MacAddress"] = r.Mac, ["IpHint"] = r.Ip },
            Tooltip = $"Send a Wake-on-LAN magic packet to {r.Description ?? r.Mac}",
        },
        GridRowAction.Edit($"/Dhcp/Reservations/edit/{r.Id:D}", "Edit reservation"),
        GridRowAction.Delete($"/Dhcp/Reservations/delete/{r.Id:D}", "Delete reservation?",
            $"Delete reservation for {r.Mac} → {r.Ip}? The IP will rejoin the general pool."));
}
