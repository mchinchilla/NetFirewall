using NetFirewall.Models.Auth;
using NetFirewall.Web.Models.Dhcp;
using NetFirewall.Web.Services;
using NetOpenGrid.Domain.Columns;

namespace NetFirewall.Web.Grids.Dhcp;

public sealed record SubnetGridRow(
    Guid Id,
    string Name,
    string? DomainName,
    string Network,
    string? Router,
    string? Interface,
    int DefaultLeaseSeconds,
    int MaxLeaseSeconds,
    int PoolCount,
    int ExclusionCount,
    bool Enabled)
{
    public static SubnetGridRow From(SubnetOverview o) => new(
        o.Subnet.Id, o.Subnet.Name, o.Subnet.DomainName, o.Subnet.Network, o.Subnet.Router?.ToString(),
        o.InterfaceName, o.Subnet.DefaultLeaseTime, o.Subnet.MaxLeaseTime, o.PoolCount, o.ExclusionCount,
        o.Subnet.Enabled);
}

/// <summary>
/// DHCP → Subnets. One row per scope; Pools / Exclusions leave the frame (<c>target=_top</c>) to
/// the subnet's nested pages, Edit/Delete go through the host drawer / confirm. Each row expands
/// into the scope's options (DNS, NTP, router, lease times, PXE) and its pools and exclusions.
/// </summary>
public static class DhcpSubnetsGrid
{
    public const string Id = "dhcp-subnets";
    public const string DefaultQuery = "sort=name:asc";

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<SubnetGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("Subnets")
            .WithEmptyMessage("No subnets configured yet. Use Add subnet to create one, or run the setup wizard.")
            .WithRowKey(s => s.Id.ToString("D"))
            .WithRowDetail(s => $"/Dhcp/Subnets/detail/{s.Id:D}")
            .AddView("Enabled", "filter=enabled:equals:true&sort=name:asc")
            .AddView("Disabled", "filter=enabled:equals:false&sort=name:asc")
            .AddView("By interface", "sort=interface:asc")
            .AddColumn("name", s => s.Name, c => c
                .Header("Subnet")
                .Searchable()
                .Pinned()
                .RawCellHtml(s => GridCell.TwoLine(s.Name, s.DomainName)))
            .AddColumn("interface", s => s.Interface ?? string.Empty, c => c
                .Header("Interface")
                .Searchable()
                .WidthCss("8rem")
                .RawCellHtml(s => GridCell.Chip("if", s.Interface)))
            .AddColumn("network", s => s.Network, c => c
                .Header("Network")
                .Comparer(IpTextComparer.Instance)
                .Searchable()
                .RawCellHtml(s => GridCell.Chip("net", s.Network, s.Network)))
            .AddColumn("router", s => s.Router ?? string.Empty, c => c
                .Header("Gateway")
                .Comparer(IpTextComparer.Instance)
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Md)
                .RawCellHtml(s => GridCell.Chip("gw", s.Router)))
            .AddColumn("lease", s => s.DefaultLeaseSeconds, c => c
                .Header("Lease")
                .HideBelow(ResponsiveBreakpoint.Lg)
                .WidthCss("8rem")
                .RawCellHtml(s => GridCell.Chip("lease", $"{s.DefaultLeaseSeconds / 3600}h/{s.MaxLeaseSeconds / 3600}h")))
            .AddColumn("enabled", s => s.Enabled, c => c
                .Header("Status")
                .WidthCss("7rem")
                .RawCellHtml(s => GridCell.Enabled(s.Enabled)))
            .AddColumn("actions", s => s.Id, c => c
                .Header("")
                .Sortable(false).Filterable(false).Searchable(false)
                .PinnedRight()
                .WidthCss("22rem")
                .RawCellHtml(Actions)),
        (sp, opts) => ScopedGridSource.From<IDhcpSubnetOverviewService, SubnetGridRow>(sp, opts, async (svc, ct) =>
            (await svc.GetAllAsync(ct)).Select(SubnetGridRow.From).ToArray()));

    private static string Actions(SubnetGridRow s) => GridCell.Actions(
        [
            ($"/Dhcp/Subnets/{s.Id}/Pools", s.PoolCount > 0 ? $"Pools ({s.PoolCount})" : "Pools"),
            ($"/Dhcp/Subnets/{s.Id}/Exclusions", s.ExclusionCount > 0 ? $"Exclusions ({s.ExclusionCount})" : "Exclusions"),
        ],
        GridRowAction.Edit($"/Dhcp/Subnets/edit/{s.Id}", $"Edit {s.Name}"),
        GridRowAction.Delete($"/Dhcp/Subnets/delete/{s.Id}", "Delete subnet?",
            $"Delete subnet '{s.Name}' ({s.Network})? Pools, exclusions and reservations bound to it will be cascaded."));
}
