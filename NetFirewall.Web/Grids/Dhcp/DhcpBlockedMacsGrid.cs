using NetFirewall.Models.Auth;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;

namespace NetFirewall.Web.Grids.Dhcp;

public sealed record BlockedMacGridRow(Guid Id, string Mac, string? Reason, DateTime CreatedAt)
{
    public static BlockedMacGridRow From(DhcpBlockedMac b) =>
        new(b.Id, LeaseGridRow.MacText(b.MacAddress.ToString()), b.Reason, b.CreatedAt);
}

/// <summary>DHCP → Access control: MAC addresses the DHCP server never answers.</summary>
public static class DhcpBlockedMacsGrid
{
    public const string Id = "dhcp-blocked-macs";

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<BlockedMacGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("Blocked devices")
            .WithEmptyMessage("No blocked devices. Use Block a device to stop the DHCP server answering a MAC address.")
            .WithRowKey(r => r.Id.ToString("D"))
            .AddColumn("mac", r => r.Mac, c => c
                .Header("MAC")
                .Searchable()
                .Pinned()
                .RawCellHtml(r => GridCell.Chip("mac", r.Mac)))
            .AddColumn("reason", r => r.Reason ?? string.Empty, c => c
                .Header("Reason")
                .Searchable()
                .RawCellHtml(r => GridCell.Muted(r.Reason)))
            .AddColumn("created", r => r.CreatedAt, c => c
                .Header("Blocked")
                .RawCellHtml(r => GridCell.When(r.CreatedAt, DateTime.UtcNow)))
            .AddColumn("actions", r => r.Id, c => c
                .Header("")
                .Sortable(false).Filterable(false).Searchable(false)
                .PinnedRight()
                .WidthCss("10rem")
                .RawCellHtml(r => GridCell.Actions(
                    GridRowAction.Edit($"/Dhcp/Access/blocked/edit/{r.Id:D}", "Edit blocked device"),
                    GridRowAction.Delete($"/Dhcp/Access/blocked/delete/{r.Id:D}", "Unblock device?",
                        $"Unblock {r.Mac}? It gets an address again on its next DHCP request.")))),
        (sp, opts) => ScopedGridSource.From<IDhcpAccessControlService, BlockedMacGridRow>(sp, opts, async (svc, ct) =>
            (await svc.GetBlockedMacsAsync(ct)).Select(BlockedMacGridRow.From).ToArray()));
}
