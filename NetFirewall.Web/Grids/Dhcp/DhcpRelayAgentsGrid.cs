using NetFirewall.Models.Auth;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;

namespace NetFirewall.Web.Grids.Dhcp;

public sealed record RelayAgentGridRow(Guid Id, string Ip, string? Description, bool Trusted)
{
    public static RelayAgentGridRow From(DhcpRelayAgent r) => new(r.Id, r.IpAddress.ToString(), r.Description, r.Trusted);
}

/// <summary>DHCP → Access control: relay agents (giaddr) and whether the server trusts them.</summary>
public static class DhcpRelayAgentsGrid
{
    public const string Id = "dhcp-relay-agents";

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<RelayAgentGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("Relay agents")
            .WithEmptyMessage("No relays listed — every relay is answered. Add one to switch trusted-relay mode on.")
            .WithRowKey(r => r.Id.ToString("D"))
            .AddColumn("ip", r => r.Ip, c => c
                .Header("Relay address (giaddr)")
                .Comparer(IpTextComparer.Instance)
                .Searchable()
                .Pinned()
                .RawCellHtml(r => GridCell.Chip("ip", r.Ip)))
            .AddColumn("trusted", r => r.Trusted, c => c
                .Header("Status")
                .RawCellHtml(r => r.Trusted ? GridCell.Status(BadgeTone.Success, "Trusted") : GridCell.Status(BadgeTone.Danger, "Refused")))
            .AddColumn("description", r => r.Description ?? string.Empty, c => c
                .Header("Description")
                .Searchable()
                .RawCellHtml(r => GridCell.Muted(r.Description)))
            .AddColumn("actions", r => r.Id, c => c
                .Header("")
                .Sortable(false).Filterable(false).Searchable(false)
                .PinnedRight()
                .WidthCss("10rem")
                .RawCellHtml(r => GridCell.Actions(
                    GridRowAction.Edit($"/Dhcp/Access/relays/edit/{r.Id:D}", "Edit relay"),
                    GridRowAction.Delete($"/Dhcp/Access/relays/delete/{r.Id:D}", "Remove relay?",
                        $"Remove {r.Ip}? If other relays stay trusted, packets from {r.Ip} will be dropped.")))),
        (sp, opts) => ScopedGridSource.From<IDhcpAccessControlService, RelayAgentGridRow>(sp, opts, async (svc, ct) =>
            (await svc.GetRelayAgentsAsync(ct)).Select(RelayAgentGridRow.From).ToArray()));
}
