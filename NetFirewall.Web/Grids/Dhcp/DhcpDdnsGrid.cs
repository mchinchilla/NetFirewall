using NetFirewall.Models.Auth;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetOpenGrid.Domain.Columns;

namespace NetFirewall.Web.Grids.Dhcp;

public enum DdnsScopeKind { Global, Subnet }

/// <summary>
/// One DDNS config as the grid sees it. The TSIG secret is deliberately NOT carried: the row
/// feeds cells, search and CSV/xlsx export, and the old table never showed it either.
/// </summary>
public sealed record DdnsGridRow(
    Guid Id,
    DdnsScopeKind Kind,
    string Scope,
    string? ForwardZone,
    string? ReverseZone,
    string? DnsServer,
    int DnsPort,
    string? TsigKeyName,
    string TsigAlgorithm,
    int Ttl,
    bool Enabled)
{
    public static DdnsGridRow From(DdnsConfig d, IReadOnlyDictionary<Guid, string> subnetNames) => new(
        d.Id,
        d.SubnetId is null ? DdnsScopeKind.Global : DdnsScopeKind.Subnet,
        ScopeName(d, subnetNames),
        d.ForwardZone, d.ReverseZone, d.DnsServer?.ToString(), d.DnsPort,
        d.TsigKeyName, d.TsigAlgorithm, d.Ttl, d.Enabled);

    /// <summary>Same wording as the old table ("Global", the subnet name, or "(unknown subnet)").</summary>
    public static string ScopeName(DdnsConfig d, IReadOnlyDictionary<Guid, string> subnetNames) =>
        d.SubnetId is null
            ? "Global"
            : subnetNames.TryGetValue(d.SubnetId.Value, out var n) ? n : "(unknown subnet)";
}

/// <summary>
/// DHCP → Dynamic DNS. A global config plus optional per-subnet overrides; the Kind column
/// (Global / Subnet) replaces the old table's sections. Rows expand into the update policy
/// (style, conflict resolution, client-update flags) from <c>/Dhcp/Ddns/detail</c>.
/// </summary>
public static class DhcpDdnsGrid
{
    public const string Id = "dhcp-ddns";
    public const string DefaultQuery = "sort=kind:asc";

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<DdnsGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("Dynamic DNS")
            .WithEmptyMessage("No DDNS configs yet. Use Add DDNS config for a global config (no subnet binding) or one per subnet to override.")
            .WithRowKey(d => d.Id.ToString("D"))
            .WithRowDetail(d => $"/Dhcp/Ddns/detail/{d.Id:D}")
            .AddView("Enabled", "filter=enabled:equals:true&sort=kind:asc")
            .AddView("Disabled", "filter=enabled:equals:false&sort=kind:asc")
            .AddColumn("scope", d => d.Scope, c => c
                .Header("Scope")
                .Searchable()
                .Pinned()
                .RawCellHtml(d => d.Kind == DdnsScopeKind.Global
                    ? GridCell.Badge(BadgeTone.Accent, "Global")
                    : $"<span class=\"font-medium\">{GridCell.Text(d.Scope)}</span>"))
            .AddColumn("kind", d => d.Kind, c => c
                .Header("Kind")
                .WidthCss("7rem")
                .HideBelow(ResponsiveBreakpoint.Lg)
                .Format(k => k == DdnsScopeKind.Global ? "Global" : "Per subnet"))
            .AddColumn("forwardZone", d => d.ForwardZone ?? string.Empty, c => c
                .Header("Forward zone")
                .Searchable()
                .RawCellHtml(d => GridCell.Chip("zone", d.ForwardZone, d.ForwardZone)))
            .AddColumn("reverseZone", d => d.ReverseZone ?? string.Empty, c => c
                .Header("Reverse zone")
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Lg)
                .RawCellHtml(d => GridCell.Chip("rev", d.ReverseZone, d.ReverseZone)))
            .AddColumn("dnsServer", d => d.DnsServer ?? string.Empty, c => c
                .Header("DNS server")
                .Comparer(IpTextComparer.Instance)
                .Searchable()
                .RawCellHtml(d => d.DnsServer is null ? GridCell.Empty : GridCell.Chip("ns", $"{d.DnsServer}:{d.DnsPort}")))
            .AddColumn("tsig", d => d.TsigKeyName ?? string.Empty, c => c
                .Header("TSIG")
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Lg)
                .RawCellHtml(d => string.IsNullOrEmpty(d.TsigKeyName)
                    ? GridCell.Empty
                    : GridCell.Chip("tsig", $"{d.TsigKeyName} · {d.TsigAlgorithm}", d.TsigAlgorithm)))
            .AddColumn("ttl", d => d.Ttl, c => c
                .Header("TTL")
                .WidthCss("6rem")
                .HideBelow(ResponsiveBreakpoint.Lg)
                .Format(t => $"{t} s"))
            .AddColumn("enabled", d => d.Enabled, c => c
                .Header("Status")
                .WidthCss("7rem")
                .RawCellHtml(d => GridCell.Enabled(d.Enabled)))
            .AddColumn("actions", d => d.Id, c => c
                .Header("")
                .Sortable(false).Filterable(false).Searchable(false)
                .PinnedRight()
                .WidthCss("9rem")
                .RawCellHtml(Actions)),
        (sp, opts) => ScopedGridSource.From<IDhcpAdminService, DdnsGridRow>(sp, opts, async (svc, ct) =>
        {
            var configs = await svc.GetDdnsConfigsAsync(ct);
            var names = (await svc.GetSubnetsAsync(ct)).ToDictionary(s => s.Id, s => s.Name);
            return configs.Select(d => DdnsGridRow.From(d, names)).ToArray();
        }));

    private static string Actions(DdnsGridRow d) => GridCell.Actions(
        GridRowAction.Edit($"/Dhcp/Ddns/edit/{d.Id}", "Edit DDNS config"),
        GridRowAction.Delete($"/Dhcp/Ddns/delete/{d.Id}", "Delete DDNS config?",
            $"Delete DDNS config for {d.Scope}? Future leases will fall back to the next config in scope (or stop updating DNS)."));
}
