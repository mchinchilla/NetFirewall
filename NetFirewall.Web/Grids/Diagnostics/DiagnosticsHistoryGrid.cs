using System.Globalization;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Diagnostics;
using NetFirewall.Web.Models.Diagnostics;
using NetOpenGrid.Domain.Columns;
using Npgsql;

namespace NetFirewall.Web.Grids.Diagnostics;

/// <summary>One persisted diagnostic run, without its params/result JSON (the row detail fetches those).</summary>
public sealed record DiagRunGridRow(
    Guid Id,
    DateTime StartedUtc,
    string Tool,
    string ToolLabel,
    string Target,
    string Status,
    string? Summary,
    string RequestedBy,
    int DurationMs)
{
    public static DiagRunGridRow From(DiagRun r) => new(
        r.Id,
        r.StartedAt,
        r.Tool,
        DiagUi.ToolLabel(r.Tool),
        r.Target ?? string.Empty,
        r.Status,
        r.Summary,
        r.RequestedBy ?? string.Empty,
        r.DurationMs ?? -1);
}

/// <summary>
/// Diagnostics → History: every persisted run (who, when, tool, target, verdict). Newest
/// first; the grid holds the latest <see cref="MaxRows"/> runs (the store pages at 200), older
/// ones age out with the retention setting. A row expands into its params + raw result; "Open"
/// shows the full rendered report in the host drawer, as the old row click did.
/// </summary>
public static class DiagnosticsHistoryGrid
{
    public const string Id = "diag-history";
    public const string DefaultQuery = "sort=started:desc";

    /// <summary>Upper bound on runs held per load. Each store page also ships the result JSON.</summary>
    public const int MaxRows = 600;
    private const int StorePage = 200;

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<DiagRunGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("Runs")
            .WithEmptyMessage("No runs recorded yet (or the history table is missing — apply migration 00041).")
            .WithRowKey(r => r.Id.ToString("D"))
            .WithRowDetail(r => $"/Diagnostics/History/detail/{r.Id:D}")
            .AddView("Problems", "filter=status:in:[\"warn\",\"fail\",\"error\",\"timeout\"]&sort=started:desc")
            .AddView("By tool", "groupby=tool&sort=started:desc")
            .AddColumn("started", r => r.StartedUtc, c => c
                .Header("When")
                .Pinned()
                .WidthCss("11rem")
                .RawCellHtml(Started))
            .AddColumn("tool", r => r.ToolLabel, c => c
                .Header("Tool")
                .Searchable()
                .RawCellHtml(r => $"<span class=\"font-medium\">{GridCell.Encode(r.ToolLabel)}</span>"))
            .AddColumn("target", r => r.Target, c => c
                .Header("Target")
                .Searchable()
                .RawCellHtml(r => GridCell.Mono(r.Target)))
            .AddColumn("status", r => r.Status, c => c
                .Header("Status")
                .WidthCss("7rem")
                .RawCellHtml(r => GridCell.Badge(StatusTone(r.Status), r.Status)))
            .AddColumn("summary", r => r.Summary ?? string.Empty, c => c
                .Header("Summary")
                .Searchable()
                .Sortable(false)
                .HideBelow(ResponsiveBreakpoint.Md)
                .RawCellHtml(r => GridCell.Muted(r.Summary)))
            .AddColumn("by", r => r.RequestedBy, c => c
                .Header("By")
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Lg)
                .RawCellHtml(r => GridCell.Text(r.RequestedBy)))
            .AddColumn("ms", r => r.DurationMs, c => c
                .Header("ms")
                .WidthCss("6rem")
                .HideBelow(ResponsiveBreakpoint.Lg)
                .RawCellHtml(r => r.DurationMs < 0 ? GridCell.Empty : GridCell.Mono(r.DurationMs.ToString())))
            .AddColumn("actions", r => r.Id, c => c
                .Header("")
                .Sortable(false).Filterable(false).Searchable(false)
                .PinnedRight()
                .WidthCss("6rem")
                .RawCellHtml(r => GridCell.Actions(OpenAction(r.Id, r.Tool)))),
        (sp, opts) => ScopedGridSource.From<IDiagnosticRunStore, DiagRunGridRow>(sp, opts, LoadAsync));

    /// <summary>The old row click: the full rendered run (tool partial, copy buttons) in the host drawer.</summary>
    public static GridRowAction OpenAction(Guid id, string tool) =>
        new(GridActionKind.Drawer, "Open", $"/Diagnostics/History/{id:D}")
        {
            DrawerTitle = $"{DiagUi.ToolLabel(tool)} · #{id.ToString("N")[..8]}",
            Tooltip = "Open the full report",
        };

    private static async Task<IReadOnlyList<DiagRunGridRow>> LoadAsync(IDiagnosticRunStore store, CancellationToken ct)
    {
        var rows = new List<DiagRunGridRow>();
        var filter = new DiagRunFilter();
        try
        {
            for (var page = 1; rows.Count < MaxRows; page++)
            {
                var (batch, total) = await store.ListAsync(filter, page, StorePage, ct);
                rows.AddRange(batch.Select(DiagRunGridRow.From));
                if (batch.Count < StorePage || rows.Count >= total) break;
            }
        }
        catch (PostgresException ex) when (ex.SqlState == "42P01")
        {
            return [];   // diag_runs missing: migration 00041 not applied (same fail-soft as the old table)
        }
        return rows.Count > MaxRows ? rows.GetRange(0, MaxRows) : rows;
    }

    private static string Started(DiagRunGridRow r) =>
        $"<span class=\"text-xs whitespace-nowrap\" title=\"{GridCell.Encode(r.StartedUtc.ToString("u", CultureInfo.InvariantCulture))}\">{GridCell.Encode(r.StartedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture))}</span>";

    /// <summary>Same mapping as <see cref="DiagUi.BadgeClass(string?)"/>.</summary>
    private static BadgeTone StatusTone(string status) => status switch
    {
        DiagRunStatus.Ok => BadgeTone.Success,
        DiagRunStatus.Warn => BadgeTone.Warning,
        DiagRunStatus.Fail => BadgeTone.Danger,
        DiagRunStatus.Running or DiagRunStatus.Busy => BadgeTone.Info,
        _ => BadgeTone.Muted,
    };
}
