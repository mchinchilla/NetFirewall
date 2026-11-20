using NetFirewall.Models.Auth;
using NetFirewall.Models.Network;
using NetFirewall.Services.Network;
using NetOpenGrid.Domain.Columns;

namespace NetFirewall.Web.Grids.Network;

/// <summary>One member of a group object, as the Value cell shows it.</summary>
public sealed record NetworkObjectMemberChip(string Type, string Name, string Value);

/// <summary>
/// One network object as the grid sees it. <see cref="ValueText"/> is the flat search key
/// (every address, or every member name for a group); the cell renders <see cref="Values"/> /
/// <see cref="Members"/> as chips.
/// </summary>
public sealed record NetworkObjectGridRow(
    Guid Id,
    string Name,
    string Type,
    string ValueText,
    IReadOnlyList<string> Values,
    IReadOnlyList<NetworkObjectMemberChip> Members,
    string? Description)
{
    public bool IsGroup => Type == NetworkObjectTypes.Group;

    public static NetworkObjectGridRow From(NetworkObject o)
    {
        var type = string.IsNullOrWhiteSpace(o.Type) ? "other" : o.Type;
        var members = (o.Members ?? [])
            .Select(m => new NetworkObjectMemberChip(m.Type, m.Name, m.Value))
            .ToArray();
        var values = type == NetworkObjectTypes.Group ? [] : NetworkObjectValues.Split(o.Value);
        var valueText = type == NetworkObjectTypes.Group
            ? string.Join(' ', members.Select(m => m.Name))
            : string.Join(' ', values);
        return new NetworkObjectGridRow(o.Id, o.Name, type, valueText, values, members, o.Description);
    }
}

/// <summary>
/// Network → Objects: named address aliases referenced by firewall rules. Each row expands
/// into its full value / member list plus the where-used panel
/// (<c>/Network/Objects/detail/{id}</c>).
/// </summary>
public static class NetworkObjectsGrid
{
    public const string Id = "network-objects";
    public const string DefaultQuery = "sort=name:asc";

    private const int MaxValueChips = 6;
    private const int MaxMemberChips = 4;

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<NetworkObjectGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("Objects")
            .WithEmptyMessage("No objects yet. Click Add object to create your first one.")
            .WithRowKey(r => r.Id.ToString("D"))
            .WithRowDetail(r => $"/Network/Objects/detail/{r.Id:D}")
            .AddView("By type", "groupby=type&sort=name:asc")
            .AddView("Groups", "filter=type:in:[\"group\"]&sort=name:asc")
            .AddColumn("name", r => r.Name, c => c
                .Header("Name")
                .Searchable()
                .Pinned()
                .RawCellHtml(r => NameCell(r.Name)))
            .AddColumn("type", r => r.Type, c => c
                .Header("Type")
                .WidthCss("7rem")
                .RawCellHtml(r => GridCell.Badge(TypeTone(r.Type), r.Type)))
            .AddColumn("value", r => r.ValueText, c => c
                .Header("Value")
                .Searchable()
                .Sortable(false)
                .RawCellHtml(ValueCell))
            .AddColumn("description", r => r.Description ?? string.Empty, c => c
                .Header("Description")
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Md)
                .RawCellHtml(r => GridCell.Muted(r.Description)))
            .AddColumn("actions", r => r.Id, c => c
                .Header("")
                .Sortable(false).Filterable(false).Searchable(false)
                .PinnedRight()
                .WidthCss("9rem")
                .RawCellHtml(Actions)),
        (sp, opts) => ScopedGridSource.From<INetworkObjectService, NetworkObjectGridRow>(sp, opts, async (svc, ct) =>
            (await svc.GetAllAsync(includeMembers: true, ct)).Select(NetworkObjectGridRow.From).ToArray()));

    /// <summary>Same tones as the old _ObjectsTable type badge.</summary>
    public static BadgeTone TypeTone(string type) => type switch
    {
        NetworkObjectTypes.Host => BadgeTone.Info,
        NetworkObjectTypes.Network => BadgeTone.Accent,
        NetworkObjectTypes.Range => BadgeTone.Warning,
        NetworkObjectTypes.Fqdn => BadgeTone.Muted,
        _ => BadgeTone.Accent,
    };

    private static string NameCell(string name) =>
        $"<span class=\"font-mono font-medium text-surface-fg\">{GridCell.Encode(name)}</span>";

    private static string ValueCell(NetworkObjectGridRow r)
    {
        if (r.IsGroup)
        {
            var parts = new List<string>(MaxMemberChips + 2) { GridCell.Chip("members", r.Members.Count.ToString()) };
            parts.AddRange(r.Members.Take(MaxMemberChips).Select(m => GridCell.Chip(m.Type, m.Name, m.Value)));
            if (r.Members.Count > MaxMemberChips) parts.Add(More(r.Members.Count - MaxMemberChips));
            return GridCell.Wrap([.. parts]);
        }

        if (r.Values.Count == 0) return GridCell.Empty;
        var chips = r.Values.Take(MaxValueChips).Select(v => GridCell.Chip(r.Type, v, v)).ToList();
        if (r.Values.Count > MaxValueChips) chips.Add(More(r.Values.Count - MaxValueChips));
        return GridCell.Wrap([.. chips]);
    }

    private static string More(int n) => $"<span class=\"text-xs text-surface-fg-muted\">+{n}</span>";

    private static string Actions(NetworkObjectGridRow r) => GridCell.Actions(
        GridRowAction.Edit($"/Network/Objects/edit/{r.Id:D}", $"Edit {r.Name}"),
        GridRowAction.Delete($"/Network/Objects/delete/{r.Id:D}", "Delete object?",
            $"Delete object '{r.Name}'? Any firewall rules referencing it by name will silently skip the reference at next apply (the resolver logs a warning)."));
}
