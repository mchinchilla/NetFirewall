using NetFirewall.Models.Auth;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Firewall;
using NetOpenGrid.Domain.Columns;

namespace NetFirewall.Web.Grids.Firewall;

public sealed record MangleRuleGridRow(
    Guid Id,
    string Chain,
    int Priority,
    string? Description,
    string? Protocol,
    string? Sources,
    string? Destinations,
    string? DestinationPorts,
    string Mark,
    RuleState Status)
{
    public string Match => string.Join(" ", new[]
    {
        Protocol is null ? null : $"proto {Protocol}",
        Sources is null ? null : $"src {Sources}",
        Destinations is null ? null : $"dst {Destinations}",
        DestinationPorts is null ? null : $"dport {DestinationPorts}",
    }.Where(s => s is not null));

    public static MangleRuleGridRow From(FwMangleRule r, IReadOnlyDictionary<Guid, string> markNames) => new(
        r.Id, r.Chain, r.Priority, r.Description,
        string.IsNullOrEmpty(r.Protocol) ? null : r.Protocol,
        Join(r.SourceAddresses), Join(r.DestinationAddresses), Join(r.DestinationPorts),
        r.MarkId is { } id && markNames.TryGetValue(id, out var n) ? n : "(no mark)",
        FirewallGridCells.State(r.Enabled));

    private static string? Join(string[]? values) => values is { Length: > 0 } ? string.Join(", ", values) : null;
}

/// <summary>
/// Firewall → Mangle rules: fwmark setters for QoS and policy routing. Evaluated top to bottom
/// by priority within each chain, so the grid opens sorted chain → priority; the old
/// Prerouting / Postrouting segmented filter is now the Chain column's checklist + two views.
/// </summary>
public static class FwMangleRulesGrid
{
    public const string Id = "fw-mangle-rules";
    public const string DefaultQuery = "sort=chain:asc&sort=priority:asc";

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<MangleRuleGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("Mangle rules")
            .WithEmptyMessage("No mangle rules yet. Click Add rule to create one.")
            .WithRowKey(r => r.Id.ToString("D"))
            .AddView("Prerouting", "filter=chain:in:[\"prerouting\"]&sort=priority:asc")
            .AddView("Postrouting", "filter=chain:in:[\"postrouting\"]&sort=priority:asc")
            .AddView("Active", "filter=status:in:[\"Active\"]&sort=chain:asc&sort=priority:asc")
            .AddColumn("chain", r => r.Chain, c => c
                .Header("Chain")
                .WidthCss("8rem")
                .RawCellHtml(r => GridCell.Badge(BadgeTone.Muted, r.Chain.ToUpperInvariant())))
            .AddColumn("priority", r => r.Priority, c => c
                .Header("Pri")
                .WidthCss("5rem")
                .Pinned()
                .RawCellHtml(r => GridCell.Muted(r.Priority.ToString())))
            .AddColumn("rule", r => r.Description ?? string.Empty, c => c
                .Header("Rule")
                .Searchable()
                .SearchMatch((r, q) => q is null
                    || (r.Description?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false)
                    || r.Match.Contains(q, StringComparison.OrdinalIgnoreCase))
                .RawCellHtml(RuleCell))
            .AddColumn("mark", r => r.Mark, c => c
                .Header("Mark")
                .Searchable()
                .RawCellHtml(r => GridCell.Chip("mark", r.Mark)))
            .AddColumn("status", r => r.Status, c => c
                .Header("Status")
                .WidthCss("7rem")
                .RawCellHtml(r => FirewallGridCells.StateBadge(r.Status)))
            .AddColumn("actions", r => r.Id, c => c
                .Header("")
                .Sortable(false).Filterable(false).Searchable(false)
                .PinnedRight()
                .WidthCss("9rem")
                .RawCellHtml(Actions)),
        (sp, opts) => ScopedGridSource.From<IFirewallService, MangleRuleGridRow>(sp, opts, async (svc, ct) =>
        {
            var rows = await svc.GetMangleRulesAsync(ct: ct);
            var marks = (await svc.GetTrafficMarksAsync(ct))
                .GroupBy(m => m.Id)
                .ToDictionary(g => g.Key, g => $"{g.First().Name} (0x{g.First().MarkValue:X})");
            return rows.Select(r => MangleRuleGridRow.From(r, marks)).ToArray();
        }));

    private static string RuleCell(MangleRuleGridRow r)
    {
        var chips = new List<string>(5);
        if (r.Protocol is not null) chips.Add(GridCell.Chip("proto", r.Protocol));
        if (r.Sources is not null) chips.Add(GridCell.Chip("src", r.Sources, r.Sources));
        if (r.Destinations is not null) chips.Add(GridCell.Chip("dst", r.Destinations, r.Destinations));
        if (r.DestinationPorts is not null) chips.Add(GridCell.Chip("dport", r.DestinationPorts, r.DestinationPorts));
        if (chips.Count == 0) chips.Add(GridCell.Chip("match", "any"));
        var title = string.IsNullOrWhiteSpace(r.Description) ? "(no description)" : r.Description;
        return $"<div class=\"leading-tight\"><div class=\"font-medium\">{GridCell.Encode(title)}</div>"
             + $"<div class=\"mt-1\">{GridCell.Wrap([.. chips])}</div></div>";
    }

    private static string Actions(MangleRuleGridRow r) => GridCell.Actions(
        GridRowAction.Edit($"/Firewall/MangleRules/edit/{r.Id}", "Edit mangle rule"),
        GridRowAction.Delete($"/Firewall/MangleRules/delete/{r.Id}", "Delete rule?",
            $"Delete mangle rule on {r.Chain} (priority {r.Priority})?"));
}
