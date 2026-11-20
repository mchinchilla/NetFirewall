using System.Globalization;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Firewall;
using NetOpenGrid.Domain.Columns;
using F = NetFirewall.Services.Firewall.AuditLogGridFields;

namespace NetFirewall.Web.Grids.Firewall;

/// <summary>
/// Firewall → Audit log: every CRUD on the firewall tables. The table grows without bound, so
/// unlike the other grids this one does NOT load a snapshot: <see cref="IAuditLogGridSource"/>
/// pushes filter / sort / value counts / paging / count down to PostgreSQL. Field ids are the
/// SQL whitelist keys (<see cref="AuditLogGridFields"/>). Each row expands into the before/after
/// JSON, fetched on demand from <c>/Firewall/AuditLog/detail/{id}</c>.
/// </summary>
public static class FwAuditLogGrid
{
    public const string Id = "fw-audit-log";
    public const string Sort = "sort=created:desc";

    /// <summary>
    /// The page opens on the last 24 h (like the old "since" default). Relative times can't be
    /// a static view, so the Index view builds this per render.
    /// </summary>
    public static string DefaultQuery(DateTime nowUtc) =>
        $"filter={F.Created}:gte:{Uri.EscapeDataString(nowUtc.AddHours(-24).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture))}&{Sort}";

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<AuditLogGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("Audit log")
            .WithEmptyMessage("No audit entries match the current filters.")
            .WithRowKey(r => r.Id.ToString("D"))
            .WithRowDetail(r => $"/Firewall/AuditLog/detail/{r.Id:D}")
            // Grouping would materialize the whole filtered set (Npgsql source caps it at 5000 rows).
            .WithGroupPanel(false)
            .AddView("All time", Sort)
            .AddView("Deletes", $"filter={F.Action}:in:[\"DELETE\"]&{Sort}")
            .AddView("Updates", $"filter={F.Action}:in:[\"UPDATE\"]&{Sort}")
            .AddColumn(F.Created, r => r.CreatedAt, c => c
                .Header("Time (UTC)")
                .Pinned()
                .WidthCss("11rem")
                .RawCellHtml(r => $"<span class=\"font-mono text-xs text-surface-fg-muted\">{GridCell.Encode(r.CreatedAt.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))}</span>"))
            .AddColumn(F.Table, r => r.TableName, c => c
                .Header("Table")
                .Searchable()
                .RawCellHtml(r => GridCell.Chip("table", TableLabel(r.TableName), r.TableName)))
            .AddColumn(F.Action, r => r.Action, c => c
                .Header("Action")
                .Searchable()
                .WidthCss("7rem")
                .RawCellHtml(r => GridCell.Badge(r.Action switch
                {
                    "INSERT" => BadgeTone.Success,
                    "UPDATE" => BadgeTone.Accent,
                    "DELETE" => BadgeTone.Danger,
                    _ => BadgeTone.Muted,
                }, r.Action)))
            .AddColumn(F.Record, r => r.RecordId, c => c
                .Header("Record")
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Md)
                .RawCellHtml(r => $"<span class=\"font-mono text-xs text-surface-fg-muted\" title=\"{GridCell.Encode(r.RecordId.ToString("D"))}\">{GridCell.Encode(r.RecordId.ToString("N")[..8])}</span>"))
            .AddColumn(F.User, r => r.UserId ?? string.Empty, c => c
                .Header("User")
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Lg)
                .RawCellHtml(r => GridCell.Muted(r.UserId))),
        (sp, opts) => sp.GetRequiredService<IAuditLogGridSource>().Create(opts));

    /// <summary>"fw_nat_rules" → "nat rules" (same label the old segmented filter used).</summary>
    public static string TableLabel(string name) =>
        (name.StartsWith("fw_", StringComparison.Ordinal) ? name[3..] : name).Replace('_', ' ');
}
