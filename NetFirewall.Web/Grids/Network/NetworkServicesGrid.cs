using NetFirewall.Models.Auth;
using NetFirewall.Models.Network;
using NetFirewall.Services.Network;
using NetOpenGrid.Domain.Columns;

namespace NetFirewall.Web.Grids.Network;

/// <summary>One L4 service as the grid sees it: text keys for filters, the port start for sorting.</summary>
public sealed record NetworkServiceGridRow(
    Guid Id,
    string Name,
    string Protocol,
    string Port,
    string Category,
    bool Builtin,
    IReadOnlyList<string> Members,
    string? Description)
{
    public const string Uncategorized = "Uncategorized";

    public static NetworkServiceGridRow From(NetworkService s) => new(
        s.Id,
        s.Name,
        s.Protocol,
        s.PortString,
        string.IsNullOrWhiteSpace(s.Category) ? Uncategorized : s.Category!,
        s.IsBuiltin,
        (s.Members ?? []).Select(m => m.Name).ToArray(),
        s.Description);
}

/// <summary>
/// Network → Services: the named L4 catalog (port + protocol). The old page's category
/// buttons are the Category column's checklist filter now (or group by it from the panel).
/// Built-in services can be edited but not deleted.
/// </summary>
public static class NetworkServicesGrid
{
    public const string Id = "network-services";
    public const string DefaultQuery = "sort=name:asc";

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<NetworkServiceGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("Services")
            .WithEmptyMessage("No services in this view. Click Add service to create one.")
            .WithRowKey(r => r.Id.ToString("D"))
            .AddView("By category", "groupby=category&sort=name:asc")
            .AddView("Custom", "filter=builtin:equals:false&sort=name:asc")
            .AddColumn("name", r => r.Name, c => c
                .Header("Name")
                .Searchable()
                .Pinned()
                .RawCellHtml(NameCell))
            .AddColumn("protocol", r => r.Protocol, c => c
                .Header("Protocol")
                .WidthCss("7rem")
                .RawCellHtml(r => GridCell.Badge(ProtocolTone(r.Protocol), r.Protocol.ToUpperInvariant())))
            .AddColumn("port", r => r.Port, c => c
                .Header("Port")
                .Comparer(PortTextComparer.Instance)
                .Searchable()
                .WidthCss("8rem")
                .RawCellHtml(r => GridCell.Chip("port", r.Port)))
            .AddColumn("category", r => r.Category, c => c
                .Header("Category")
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Md)
                .RawCellHtml(r => GridCell.Muted(r.Category)))
            .AddColumn("builtin", r => r.Builtin, c => c
                .Header("Origin")
                .WidthCss("7rem")
                .HideBelow(ResponsiveBreakpoint.Lg)
                .RawCellHtml(r => r.Builtin ? GridCell.Badge(BadgeTone.Muted, "builtin") : GridCell.Badge(BadgeTone.Info, "custom")))
            .AddColumn("description", r => r.Description ?? string.Empty, c => c
                .Header("Description")
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Lg)
                .RawCellHtml(r => GridCell.Muted(r.Description)))
            .AddColumn("actions", r => r.Id, c => c
                .Header("")
                .Sortable(false).Filterable(false).Searchable(false)
                .PinnedRight()
                .WidthCss("9rem")
                .RawCellHtml(Actions)),
        (sp, opts) => ScopedGridSource.From<INetworkServiceService, NetworkServiceGridRow>(sp, opts, async (svc, ct) =>
            (await svc.GetAllAsync(includeMembers: true, ct)).Select(NetworkServiceGridRow.From).ToArray()));

    /// <summary>Same tones as the old _ServicesTable protocol badge.</summary>
    private static BadgeTone ProtocolTone(string protocol) => protocol switch
    {
        NetworkServiceProtocols.Tcp => BadgeTone.Accent,
        NetworkServiceProtocols.Udp => BadgeTone.Info,
        NetworkServiceProtocols.TcpUdp => BadgeTone.Warning,
        NetworkServiceProtocols.Icmp => BadgeTone.Success,
        _ => BadgeTone.Muted,
    };

    private static string NameCell(NetworkServiceGridRow r)
    {
        var name = $"<span class=\"font-mono font-medium text-surface-fg\">{GridCell.Encode(r.Name)}</span>";
        return r.Members.Count > 0
            ? GridCell.Wrap(name, $"<span class=\"badge badge-accent\" title=\"{GridCell.Encode(string.Join(", ", r.Members))}\">group · {r.Members.Count}</span>")
            : name;
    }

    private static string Actions(NetworkServiceGridRow r) => GridCell.Actions(
        GridRowAction.Edit($"/Network/Services/edit/{r.Id:D}", $"Edit {r.Name}"),
        r.Builtin
            ? null
            : GridRowAction.Delete($"/Network/Services/delete/{r.Id:D}", "Delete service?",
                $"Delete service '{r.Name}'? Any firewall rules referencing it by name will silently skip the reference at next apply."));
}

/// <summary>Orders "22", "443", "10000-20000" by the first port number, then by the text.</summary>
internal sealed class PortTextComparer : IComparer<string>
{
    public static readonly PortTextComparer Instance = new();

    public int Compare(string? x, string? y)
    {
        var c = Start(x).CompareTo(Start(y));
        return c != 0 ? c : string.CompareOrdinal(x, y);
    }

    private static int Start(string? text)
    {
        if (string.IsNullOrEmpty(text)) return int.MaxValue;
        var span = text.AsSpan();
        var dash = span.IndexOf('-');
        if (dash >= 0) span = span[..dash];
        return int.TryParse(span, out var n) ? n : int.MaxValue;
    }
}
