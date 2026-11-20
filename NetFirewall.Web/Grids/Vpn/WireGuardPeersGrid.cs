using NetFirewall.Models.Auth;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Vpn;
using NetOpenGrid.Domain.Columns;

namespace NetFirewall.Web.Grids.Vpn;

/// <summary>
/// One WireGuard peer as the grids see it. Carries the PUBLIC key only: the preshared key
/// never enters a row (rows are rendered into the frame and exported to CSV/xlsx).
/// </summary>
public sealed record WgPeerGridRow(
    Guid Id,
    string Name,
    string? Description,
    string Role,
    string Endpoint,
    IReadOnlyList<string> AllowedIps,
    string AllowedIpsText,
    string Access,
    string PublicKey,
    bool Enabled)
{
    public bool IsTunnel => WireGuardPeersGrid.IsTunnelRole(Role);

    public static WgPeerGridRow From(WgPeer p)
    {
        var role = string.IsNullOrEmpty(p.Role) ? "client" : p.Role.ToLowerInvariant();
        return new WgPeerGridRow(
            p.Id, p.Name, p.Description,
            WireGuardPeersGrid.IsTunnelRole(role) ? (role == "upstream" ? "Upstream" : "Site") : "Client",
            p.Endpoint ?? string.Empty,
            p.AllowedIps,
            string.Join(' ', p.AllowedIps),
            AccessLabel(p),
            p.PublicKey,
            p.Enabled);
    }

    /// <summary>Same wording as the old _PeersTable "Access" column.</summary>
    public static string AccessLabel(WgPeer p)
    {
        var lan = (p.RouteMode ?? "split") switch
        {
            "restricted" => "restricted LAN",
            "none" => "no LAN",
            _ => "LAN",
        };
        return p.AllowInternet ? (p.RouteMode == "none" ? "internet only" : $"{lan} + internet") : lan;
    }
}

/// <summary>
/// VPN → WireGuard: two grids on the WireGuard page, one per peer family. Tunnels (upstream
/// egress + site-to-site, health-monitored) and VPN clients (road-warriors). Each row expands
/// into the peer's config summary plus live handshake / transfer from the daemon
/// (<c>/Vpn/WireGuard/Peers/detail/{id}</c>).
/// </summary>
public static class WireGuardPeersGrid
{
    public const string TunnelsId = "wg-tunnels";
    public const string ClientsId = "wg-clients";
    public const string DefaultQuery = "sort=name:asc";

    private static readonly string[] Roles = [UserRoles.Admin, UserRoles.Operator];

    public static bool IsTunnelRole(string role) =>
        role.Equals("upstream", StringComparison.OrdinalIgnoreCase)
        || role.Equals("site", StringComparison.OrdinalIgnoreCase);

    public static void Register(NetFirewallGridBuilder grids)
    {
        grids.Add<WgPeerGridRow>(
            TunnelsId,
            Roles,
            o => o
                .WithTitle("Tunnels")
                .WithEmptyMessage("No tunnels yet. Click Add tunnel to dial an upstream VPN server or link another site.")
                .WithRowKey(r => r.Id.ToString("D"))
                .WithRowDetail(Detail)
                .AddView("By role", "groupby=role&sort=name:asc")
                .AddView("Active", "filter=enabled:equals:true&sort=name:asc")
                .AddColumn("name", r => r.Name, c => c
                    .Header("Name")
                    .Searchable()
                    .Pinned()
                    .RawCellHtml(r => GridCell.TwoLine(r.Name, r.Description)))
                .AddColumn("role", r => r.Role, c => c
                    .Header("Role")
                    .WidthCss("7rem")
                    .RawCellHtml(r => GridCell.Badge(BadgeTone.Accent, r.Role)))
                .AddColumn("endpoint", r => r.Endpoint, c => c
                    .Header("Endpoint")
                    .Searchable()
                    .RawCellHtml(r => GridCell.Chip("ep", r.Endpoint, r.Endpoint)))
                .AddColumn("allowedIps", r => r.AllowedIpsText, c => c
                    .Header("Routed")
                    .Searchable()
                    .Sortable(false)
                    .HideBelow(ResponsiveBreakpoint.Lg)
                    .RawCellHtml(r => Chips("via", r.AllowedIps, 3)))
                .AddColumn("key", r => r.PublicKey, c => c
                    .Header("Key")
                    .Sortable(false)
                    .HideBelow(ResponsiveBreakpoint.Md)
                    .RawCellHtml(KeyChip))
                .AddColumn("enabled", r => r.Enabled, c => c
                    .Header("Status")
                    .WidthCss("7rem")
                    .RawCellHtml(Status))
                .AddColumn("actions", r => r.Id, c => c
                    .Header("")
                    .Sortable(false).Filterable(false).Searchable(false)
                    .PinnedRight()
                    .WidthCss("9rem")
                    .RawCellHtml(Actions)),
            (sp, opts) => ScopedGridSource.From<IWireGuardService, WgPeerGridRow>(sp, opts,
                (wg, ct) => LoadAsync(wg, tunnels: true, ct)));

        grids.Add<WgPeerGridRow>(
            ClientsId,
            Roles,
            o => o
                .WithTitle("VPN clients")
                .WithEmptyMessage("No clients yet. Click Add client to issue a config for a laptop, phone, etc.")
                .WithRowKey(r => r.Id.ToString("D"))
                .WithRowDetail(Detail)
                .AddView("Active", "filter=enabled:equals:true&sort=name:asc")
                .AddView("Off", "filter=enabled:equals:false&sort=name:asc")
                .AddColumn("name", r => r.Name, c => c
                    .Header("Name")
                    .Searchable()
                    .Pinned()
                    .RawCellHtml(r => GridCell.TwoLine(r.Name, r.Description)))
                .AddColumn("allowedIps", r => r.AllowedIpsText, c => c
                    .Header("Allowed IPs")
                    .Searchable()
                    .Comparer(IpTextComparer.Instance)
                    .RawCellHtml(r => Chips("ip", r.AllowedIps, 4)))
                .AddColumn("access", r => r.Access, c => c
                    .Header("Access")
                    .HideBelow(ResponsiveBreakpoint.Lg)
                    .RawCellHtml(r => GridCell.Badge(BadgeTone.Muted, r.Access)))
                .AddColumn("key", r => r.PublicKey, c => c
                    .Header("Key")
                    .Sortable(false)
                    .HideBelow(ResponsiveBreakpoint.Md)
                    .RawCellHtml(KeyChip))
                .AddColumn("enabled", r => r.Enabled, c => c
                    .Header("Status")
                    .WidthCss("7rem")
                    .RawCellHtml(Status))
                .AddColumn("actions", r => r.Id, c => c
                    .Header("")
                    .Sortable(false).Filterable(false).Searchable(false)
                    .PinnedRight()
                    .WidthCss("9rem")
                    .RawCellHtml(Actions)),
            (sp, opts) => ScopedGridSource.From<IWireGuardService, WgPeerGridRow>(sp, opts,
                (wg, ct) => LoadAsync(wg, tunnels: false, ct)));
    }

    private static async Task<IReadOnlyList<WgPeerGridRow>> LoadAsync(IWireGuardService wg, bool tunnels, CancellationToken ct)
    {
        var server = await wg.GetServerAsync(ct);
        if (server is null) return [];
        var peers = await wg.GetPeersAsync(server.Id, ct);
        return peers.Where(p => IsTunnelRole(p.Role ?? string.Empty) == tunnels).Select(WgPeerGridRow.From).ToArray();
    }

    private static string Detail(WgPeerGridRow r) => $"/Vpn/WireGuard/Peers/detail/{r.Id:D}";

    private static string Status(WgPeerGridRow r) =>
        r.Enabled ? GridCell.Badge(BadgeTone.Success, "Active") : GridCell.Badge(BadgeTone.Muted, "Off");

    private static string KeyChip(WgPeerGridRow r)
    {
        var shortKey = r.PublicKey.Length > 12 ? r.PublicKey[..12] + "…" : r.PublicKey;
        return GridCell.Chip("key", shortKey, r.PublicKey);
    }

    private static string Chips(string label, IReadOnlyList<string> values, int max)
    {
        if (values.Count == 0) return GridCell.Empty;
        var parts = values.Take(max).Select(v => GridCell.Chip(label, v, v)).ToList();
        if (values.Count > max) parts.Add($"<span class=\"text-xs text-surface-fg-muted\">+{values.Count - max}</span>");
        return GridCell.Wrap([.. parts]);
    }

    private static string Actions(WgPeerGridRow r) => GridCell.Actions(
        GridRowAction.Edit($"/Vpn/WireGuard/Peers/edit/{r.Id:D}", $"Edit {r.Name}"),
        r.IsTunnel
            ? GridRowAction.Delete($"/Vpn/WireGuard/Peers/delete/{r.Id:D}", "Delete tunnel?",
                $"Delete tunnel '{r.Name}'? Traffic routed through it will stop flowing until you set it up again.")
            : GridRowAction.Delete($"/Vpn/WireGuard/Peers/delete/{r.Id:D}", "Delete client?",
                $"Delete client '{r.Name}'? Their config will stop working — there's no way to recover the private key, you'd have to issue a new client."));
}
