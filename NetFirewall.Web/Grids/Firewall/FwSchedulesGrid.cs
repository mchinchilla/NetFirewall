using NetFirewall.Models.Auth;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Firewall;
using NetOpenGrid.Domain.Columns;

namespace NetFirewall.Web.Grids.Firewall;

/// <summary>Off = disabled; ActiveNow = enabled and inside its window; Idle = enabled, outside it.</summary>
public enum ScheduleState { ActiveNow, Idle, Off }

public sealed record ScheduleGridRow(
    Guid Id,
    string Name,
    string? Description,
    TimeSpan Start,
    TimeSpan End,
    string Timezone,
    string Days,
    ScheduleState Status)
{
    public string Window => $"{Start:hh\\:mm}–{End:hh\\:mm}";

    public static ScheduleGridRow From(FwSchedule s, DateTimeOffset nowUtc) => new(
        s.Id, s.Name, s.Description, s.StartTime, s.EndTime, s.Timezone, FormatDays(s.DaysOfWeek),
        !s.Enabled ? ScheduleState.Off : s.IsActiveAt(nowUtc) ? ScheduleState.ActiveNow : ScheduleState.Idle);

    /// <summary>Same wording as the old table: Daily / Weekdays / Weekends / "Mon Wed Fri".</summary>
    public static string FormatDays(int[] dows)
    {
        if (dows.Length == 7) return "Daily";
        if (dows.SequenceEqual(new[] { 1, 2, 3, 4, 5 })) return "Weekdays";
        if (dows.SequenceEqual(new[] { 0, 6 })) return "Weekends";
        var names = new[] { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
        return string.Join(" ", dows.Where(d => d is >= 0 and <= 6).OrderBy(d => d).Select(d => names[d]));
    }
}

/// <summary>
/// Firewall → Schedules: time windows that gate filter rules. Status is evaluated at load
/// time (each refresh), like the lease state on the DHCP grid.
/// </summary>
public static class FwSchedulesGrid
{
    public const string Id = "fw-schedules";
    public const string DefaultQuery = "sort=name:asc";

    public static void Register(NetFirewallGridBuilder grids) => grids.Add<ScheduleGridRow>(
        Id,
        [UserRoles.Admin, UserRoles.Operator],
        o => o
            .WithTitle("Schedules")
            .WithEmptyMessage("No schedules yet. Click Add schedule to create one.")
            .WithRowKey(r => r.Id.ToString("D"))
            .AddView("Active now", "filter=status:in:[\"ActiveNow\"]&sort=name:asc")
            .AddView("Enabled", "filter=status:in:[\"ActiveNow\",\"Idle\"]&sort=name:asc")
            .AddColumn("name", r => r.Name, c => c
                .Header("Name")
                .Searchable()
                .SearchMatch((r, q) => q is null
                    || r.Name.Contains(q, StringComparison.OrdinalIgnoreCase)
                    || (r.Description?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false))
                .Pinned()
                .RawCellHtml(r => GridCell.TwoLine(r.Name, r.Description)))
            .AddColumn("start", r => r.Start, c => c
                .Header("Window")
                .Filterable(false)
                .RawCellHtml(r => GridCell.Chip("window", r.Window)))
            .AddColumn("timezone", r => r.Timezone, c => c
                .Header("Timezone")
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Lg)
                .RawCellHtml(r => GridCell.Chip("tz", r.Timezone)))
            .AddColumn("days", r => r.Days, c => c
                .Header("Days")
                .Searchable()
                .HideBelow(ResponsiveBreakpoint.Md)
                .RawCellHtml(r => GridCell.Chip("days", r.Days)))
            .AddColumn("status", r => r.Status, c => c
                .Header("Status")
                .WidthCss("8rem")
                .FilterValueLabels((ctx, ct) => Task.FromResult(StatusLabels))
                .RawCellHtml(r => r.Status switch
                {
                    ScheduleState.ActiveNow => GridCell.Status(BadgeTone.Success, "Active now"),
                    ScheduleState.Idle => GridCell.Badge(BadgeTone.Muted, "Idle"),
                    _ => GridCell.Badge(BadgeTone.Muted, "Off"),
                }))
            .AddColumn("actions", r => r.Id, c => c
                .Header("")
                .Sortable(false).Filterable(false).Searchable(false)
                .PinnedRight()
                .WidthCss("15rem")
                .RawCellHtml(Actions)),
        (sp, opts) => ScopedGridSource.From<IScheduleService, ScheduleGridRow>(sp, opts, async (svc, ct) =>
        {
            var now = DateTimeOffset.UtcNow;
            return (await svc.GetAllAsync(ct)).Select(s => ScheduleGridRow.From(s, now)).ToArray();
        }));

    private static readonly IReadOnlyDictionary<string, string> StatusLabels = new Dictionary<string, string>
    {
        [nameof(ScheduleState.ActiveNow)] = "Active now",
        [nameof(ScheduleState.Idle)] = "Idle",
        [nameof(ScheduleState.Off)] = "Off",
    };

    private static string Actions(ScheduleGridRow r) => GridCell.Actions(
        new GridRowAction(GridActionKind.Drawer, "Apply to devices", $"/Firewall/FilterRules/time-policy?scheduleId={r.Id}")
        {
            DrawerTitle = $"Apply {r.Name}",
        },
        GridRowAction.Edit($"/Firewall/Schedules/edit/{r.Id}", $"Edit {r.Name}"),
        GridRowAction.Delete($"/Firewall/Schedules/delete/{r.Id}", "Delete schedule?",
            $"Delete schedule '{r.Name}'? Time-limit policies attached to it will be removed. Other filter rules that used this window will be disabled — not left always-on."));
}
