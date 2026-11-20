using System.Globalization;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetOpenGrid.Domain.Columns;

namespace NetFirewall.Web.Grids.Dhcp;

public enum LeaseState { Active, Expired }

/// <summary>One lease as the grid sees it: text keys for filtering, UTC times for sorting.</summary>
public sealed record LeaseGridRow(Guid Id, string Ip, string Mac, string? Hostname, DateTime StartUtc, DateTime EndUtc)
{
    public LeaseState State(DateTime nowUtc) => EndUtc <= nowUtc ? LeaseState.Expired : LeaseState.Active;

    public static LeaseGridRow From(DhcpLease l) =>
        new(l.Id, l.IpAddress.ToString(), MacText(l.MacAddress.ToString()), l.Hostname, l.StartTime, l.EndTime);

    /// <summary>PhysicalAddress prints "AABBCCDDEEFF"; operators read aa:bb:cc:dd:ee:ff.</summary>
    public static string MacText(string raw)
    {
        // Runs once per lease row: decode into a stack buffer, format once (no Substring/LINQ).
        Span<byte> mac = stackalloc byte[6];
        return raw.Length == 12 && System.Convert.FromHexString(raw, mac, out _, out var written) == System.Buffers.OperationStatus.Done && written == 6
            ? NetFirewall.Models.Wol.MacAddressText.Format(mac, lowercase: true)
            : raw;
    }
}

/// <summary>
/// DHCP → Leases. Every lease on record (active and expired) in one grid: the page opens on the
/// "Active" filter, the State column has an Excel-style checklist with counts, grouping by
/// state or host works from the group panel, and each row expands into a detail panel
/// (timing, reservation, subnet) fetched on demand from <c>/Dhcp/Leases/detail</c>.
/// </summary>
public static class DhcpLeasesGrid
{
    public const string Id = "dhcp-leases";
    public const string DefaultQuery = "filter=state:in:[\"Active\"]&sort=ip:asc";

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<LeaseGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator, UserRoles.Viewer],
        o => o
            .WithTitle("Leases")
            .WithEmptyMessage("No leases match. Plug something in and this page will pick it up.")
            .WithRowKey(l => l.Id.ToString("D"))
            .WithRowDetail(l => $"/Dhcp/Leases/detail/{Uri.EscapeDataString(l.Mac)}")
            .AddView("Active", "filter=state:in:[\"Active\"]&sort=ip:asc")
            .AddView("Expiring soon", "filter=state:in:[\"Active\"]&sort=expires:asc")
            .AddView("Expired", "filter=state:in:[\"Expired\"]&sort=expires:desc")
            .AddColumn("ip", l => l.Ip, c => c
                .Header("IP address")
                .Comparer(IpTextComparer.Instance)
                .Searchable()
                .Pinned()
                .RawCellHtml(l => GridCell.Chip("ip", l.Ip)))
            .AddColumn("mac", l => l.Mac, c => c
                .Header("MAC")
                .Searchable()
                .RawCellHtml(l => GridCell.Chip("mac", l.Mac)))
            .AddColumn("hostname", l => l.Hostname ?? string.Empty, c => c
                .Header("Host")
                .Searchable()
                .RawCellHtml(l => GridCell.Text(l.Hostname)))
            .AddColumn("started", l => l.StartUtc, c => c
                .Header("Leased")
                .HideBelow(ResponsiveBreakpoint.Lg)
                .Format(d => d.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture)))
            .AddColumn("expires", l => l.EndUtc, c => c
                .Header("Expires")
                .RawCellHtml(l => GridCell.When(l.EndUtc, DateTime.UtcNow)))
            .AddColumn("state", l => l.State(DateTime.UtcNow), c => c
                .Header("State")
                .WidthCss("7rem")
                .RawCellHtml(l => l.State(DateTime.UtcNow) == LeaseState.Active
                    ? GridCell.Status(BadgeTone.Success, "Active")
                    : GridCell.Status(BadgeTone.Muted, "Expired")))
            .AddColumn("actions", l => l.Id, c => c
                .Header("")
                .Sortable(false).Filterable(false).Searchable(false)
                .PinnedRight()
                .WidthCss("11rem")
                .RawCellHtml(Actions)),
        (sp, opts) => ScopedGridSource.From<IDhcpAdminService, LeaseGridRow>(sp, opts, async (svc, ct) =>
            (await svc.GetAllLeasesAsync(includeExpired: true, ct: ct)).Select(LeaseGridRow.From).ToArray()));

    private static string Actions(LeaseGridRow l)
    {
        // Wake on every row: an expired lease is usually a machine that is asleep.
        var wake = new GridRowAction(GridActionKind.Post, "Wake", "/Network/WakeOnLan/wake")
        {
            Values = new Dictionary<string, string> { ["MacAddress"] = l.Mac, ["IpHint"] = l.Ip },
            Tooltip = $"Send a Wake-on-LAN magic packet to {l.Hostname ?? l.Mac}",
        };
        var release = l.State(DateTime.UtcNow) == LeaseState.Active
            ? new GridRowAction(GridActionKind.Post, "Release", $"/Dhcp/Leases/release/{l.Id:D}")
            {
                Danger = true,
                Confirm = new GridConfirm("Release lease?",
                    $"Release lease {l.Ip} (MAC {l.Mac})? The client will need to renew via DHCPREQUEST.",
                    "Release", "warning"),
            }
            : null;
        return GridCell.Actions(wake, release);
    }
}
