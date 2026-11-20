using System.Text;
using NetFirewall.Models.Firewall;

namespace NetFirewall.Web.Grids.Firewall;

/// <summary>Enabled flag of a firewall object, as an enum so the Status column gets an Excel-style checklist.</summary>
public enum RuleState { Active, Off }

/// <summary>
/// Cell builders shared by the Firewall grids that <see cref="GridCell"/> does not have yet
/// (interface chip, top-level link button). Same contract: every value is HTML-encoded.
/// Pure functions, no state, no IO.
/// </summary>
internal static class FirewallGridCells
{
    public static RuleState State(bool enabled) => enabled ? RuleState.Active : RuleState.Off;

    /// <summary>The old tables' status pill: "Active" (success) / "Off" (muted).</summary>
    public static string StateBadge(RuleState state) => state == RuleState.Active
        ? GridCell.Status(BadgeTone.Success, "Active")
        : GridCell.Status(BadgeTone.Muted, "Off");

    /// <summary>Interface name + type, keyed by id, for the rows that only carry an InterfaceId.</summary>
    public static IReadOnlyDictionary<Guid, FwInterface> ById(IEnumerable<FwInterface> interfaces) =>
        interfaces.GroupBy(i => i.Id).ToDictionary(g => g.Key, g => g.First());

    public static (string Name, string? Type) Iface(IReadOnlyDictionary<Guid, FwInterface> ifaces, Guid? id) =>
        id is { } v && ifaces.TryGetValue(v, out var i) ? (i.Name, i.Type) : ("any", null);

    /// <summary>Same markup as the <c>_IfaceChip</c> partial (iface-chip-{wan,lan,vpn,any}).</summary>
    public static string IfaceChip(string name, string? type, string? dir = null)
    {
        var isAny = string.Equals(name, "any", StringComparison.OrdinalIgnoreCase);
        var cls = isAny ? "iface-chip-any" : (type ?? "").Trim().ToLowerInvariant() switch
        {
            "wan" => "iface-chip-wan",
            "lan" => "iface-chip-lan",
            "vpn" => "iface-chip-vpn",
            _ => "",
        };
        var sb = new StringBuilder(200);
        sb.Append("<span class=\"iface-chip ").Append(cls).Append("\">");
        if (!string.IsNullOrEmpty(dir)) sb.Append("<span class=\"iface-chip-dir\">").Append(GridCell.Encode(dir)).Append("</span>");
        sb.Append("<span class=\"iface-chip-name\">").Append(GridCell.Encode(name)).Append("</span>");
        if (!isAny && !string.IsNullOrWhiteSpace(type)) sb.Append("<span class=\"iface-chip-role\">").Append(GridCell.Encode(type)).Append("</span>");
        sb.Append("</span>");
        return sb.ToString();
    }

    /// <summary>
    /// A ghost-button link that navigates the HOST page (<c>target="_top"</c>), not the grid frame.
    /// Prepended to the <see cref="GridCell.Actions"/> buttons in one right-aligned row.
    /// </summary>
    public static string ActionsWithLink(string href, string label, params GridRowAction?[] actions) =>
        GridCell.Actions([(href, label)], actions);
}
