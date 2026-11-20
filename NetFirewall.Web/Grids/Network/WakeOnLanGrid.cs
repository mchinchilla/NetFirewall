using System.Globalization;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Wol;
using NetFirewall.Web.Models.Network;
using NetFirewall.Web.Services;
using NetOpenGrid.Application.Options;
using NetOpenGrid.Domain.Columns;

namespace NetFirewall.Web.Grids.Network;

/// <summary>
/// One saved Wake-on-LAN device with its ARP presence. <see cref="Status"/> is the presence
/// label ("online", "idle", …, or "unknown" when the daemon could not be asked) so the
/// Status column gets a checklist filter; <see cref="LastWokenUtc"/> is
/// <see cref="DateTime.MinValue"/> for "never" so it sorts last when descending.
/// </summary>
public sealed record WolDeviceGridRow(
    Guid Id,
    string Name,
    string Mac,
    string Ip,
    string? Hostname,
    string? Description,
    string Interface,
    int Port,
    string Status,
    BadgeTone StatusTone,
    string StatusTitle,
    DateTime LastWokenUtc,
    string? LastWokenBy)
{
    public const string Unknown = "unknown";

    public static WolDeviceGridRow From(WolDeviceRow row, string? presenceError)
    {
        var d = row.Device;
        var p = row.Presence;
        var (status, tone, title) = presenceError is null
            ? (p.Label, ToneOf(p.BadgeClass), p.Title)
            : (Unknown, BadgeTone.Warning, $"Status unavailable: {presenceError}");
        return new WolDeviceGridRow(
            d.Id, d.Name, d.MacAddress, d.KnownIp ?? p.Ip ?? string.Empty, d.KnownHostname, d.Description,
            d.Interface, d.Port, status, tone, title,
            d.LastWokenAt ?? DateTime.MinValue, d.LastWokenBy);
    }

    private static BadgeTone ToneOf(string badgeClass) => badgeClass switch
    {
        "badge-success" => BadgeTone.Success,
        "badge-info" => BadgeTone.Info,
        "badge-danger" => BadgeTone.Danger,
        "badge-warning" => BadgeTone.Warning,
        _ => BadgeTone.Muted,
    };
}

/// <summary>
/// Network → Wake-on-LAN saved devices. Presence comes from the firewall's ARP table, so the
/// host frame re-reads the rows every 15 s (that replaces the old out-of-band badge poll).
/// Wake one = row action; wake the ticked ones = the "wake" bulk action, which only
/// announces <c>netgrid:bulk-action</c> to the host page (site.js posts <c>wake-many</c>).
/// </summary>
public static class WakeOnLanGrid
{
    public const string Id = "wol-devices";
    public const string DefaultQuery = "sort=name:asc";
    public const string WakeAction = "wake";

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<WolDeviceGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("Devices")
            .WithEmptyMessage("No saved devices yet. Click Add device for machines you wake often, or use the Wake button next to a DHCP reservation or lease.")
            .EnableRowSelection(r => r.Id.ToString("D"))
            .AddBulkAction(WakeAction, a => a
                .Label("Wake selected")
                .Tone(BulkActionTone.Primary))
            .AddView("Online", "filter=status:in:[\"online\"]&sort=name:asc")
            .AddView("Recently woken", "sort=lastWoken:desc")
            .AddColumn("name", r => r.Name, c => c
                .Header("Device")
                .Searchable()
                .Pinned()
                .RawCellHtml(r => GridCell.TwoLine(r.Name, r.Description)))
            .AddColumn("mac", r => r.Mac, c => c
                .Header("MAC")
                .Searchable()
                .RawCellHtml(r => GridCell.Chip("mac", r.Mac, r.Mac)))
            .AddColumn("ip", r => r.Ip, c => c
                .Header("IP")
                .Comparer(IpTextComparer.Instance)
                .Searchable()
                .RawCellHtml(r => GridCell.Chip("ip", r.Ip)))
            .AddColumn("hostname", r => r.Hostname ?? string.Empty, c => c
                .Header("Host")
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Lg)
                .RawCellHtml(r => GridCell.Muted(r.Hostname)))
            .AddColumn("interface", r => r.Interface, c => c
                .Header("Interface")
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Md)
                .RawCellHtml(InterfaceCell))
            .AddColumn("status", r => r.Status, c => c
                .Header("Status")
                .WidthCss("7rem")
                .RawCellHtml(r => TitledBadge(r.StatusTone, r.Status, r.StatusTitle)))
            .AddColumn("lastWoken", r => r.LastWokenUtc, c => c
                .Header("Last woken")
                .HideBelow(ResponsiveBreakpoint.Lg)
                .RawCellHtml(LastWokenCell))
            .AddColumn("actions", r => r.Id, c => c
                .Header("")
                .Sortable(false).Filterable(false).Searchable(false)
                .PinnedRight()
                .WidthCss("13rem")
                .RawCellHtml(Actions)),
        (sp, opts) => ScopedGridSource.From<IWolDeviceListService, WolDeviceGridRow>(sp, opts, async (svc, ct) =>
        {
            var table = await svc.GetAsync(ct);
            return table.Rows.Select(r => WolDeviceGridRow.From(r, table.PresenceError)).ToArray();
        }));

    private static string InterfaceCell(WolDeviceGridRow r)
    {
        var chip = GridCell.Chip("dev", r.Interface);
        return r.Port == WolDefaults.Port
            ? chip
            : GridCell.Wrap(chip, $"<span class=\"text-xs font-mono text-surface-fg-muted\">udp/{r.Port}</span>");
    }

    private static string LastWokenCell(WolDeviceGridRow r)
    {
        if (r.LastWokenUtc == DateTime.MinValue) return GridCell.Muted("never");
        var local = r.LastWokenUtc.ToLocalTime();
        var text = local.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)
            + (r.LastWokenBy is null ? string.Empty : $" · {r.LastWokenBy}");
        return $"<span class=\"text-xs text-surface-fg-muted\" title=\"{GridCell.Encode(local.ToString("u", CultureInfo.InvariantCulture))}\">{GridCell.Encode(text)}</span>";
    }

    /// <summary>A badge with a tooltip (the presence explanation). Candidate for GridCell.Badge(…, title).</summary>
    private static string TitledBadge(BadgeTone tone, string text, string title)
    {
        var badge = GridCell.Badge(tone, text);
        return badge.Insert("<span".Length, $" title=\"{GridCell.Encode(title)}\"");
    }

    private static string Actions(WolDeviceGridRow r) => GridCell.Actions(
        new GridRowAction(GridActionKind.Post, "Wake", $"/Network/WakeOnLan/wake/{r.Id:D}")
        {
            Tooltip = $"Send a Wake-on-LAN magic packet to {r.Name}",
        },
        GridRowAction.Edit($"/Network/WakeOnLan/edit/{r.Id:D}", "Edit device"),
        GridRowAction.Delete($"/Network/WakeOnLan/delete/{r.Id:D}", "Remove device?",
            $"Remove {r.Name} ({r.Mac}) from the Wake-on-LAN list? DHCP is not touched.", "Remove"));
}
