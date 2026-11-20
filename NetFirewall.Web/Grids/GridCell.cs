using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace NetFirewall.Web.Grids;

/// <summary>Colour of a status pill. Maps 1:1 to the <c>.badge-*</c> classes in site.css.</summary>
public enum BadgeTone { Accent, Success, Warning, Danger, Info, Muted }

/// <summary>What a row-action button does when clicked inside a grid frame.</summary>
public enum GridActionKind
{
    /// <summary>GET <see cref="GridRowAction.Url"/> into the host's drawer (edit forms).</summary>
    Drawer,

    /// <summary>POST <see cref="GridRowAction.Url"/> through htmx (antiforgery, elevation, toast all apply).</summary>
    Post,
}

/// <summary>Confirmation dialog shown by the host before a <see cref="GridActionKind.Post"/> runs.</summary>
public sealed record GridConfirm(string Title, string Message, string ConfirmLabel = "Confirm", string Level = "danger");

/// <summary>
/// One button of a row's action cell. The grid lives in a same-origin iframe with its own
/// htmx/Alpine, so the button does nothing by itself: site.js (<c>NetFw.grids</c>) listens for
/// clicks on <c>[data-nf-action]</c> inside every grid frame and replays them in the host page,
/// where the drawer, the confirm dialog, the elevation modal and the toasts live.
/// </summary>
public sealed record GridRowAction(GridActionKind Kind, string Label, string Url)
{
    public string? DrawerTitle { get; init; }
    public GridConfirm? Confirm { get; init; }
    public IReadOnlyDictionary<string, string>? Values { get; init; }
    public bool Danger { get; init; }
    public string? Tooltip { get; init; }

    public static GridRowAction Edit(string url, string drawerTitle) =>
        new(GridActionKind.Drawer, "Edit", url) { DrawerTitle = drawerTitle };

    public static GridRowAction Delete(string url, string title, string message, string confirmLabel = "Delete") =>
        new(GridActionKind.Post, "Delete", url) { Danger = true, Confirm = new GridConfirm(title, message, confirmLabel) };
}

/// <summary>
/// HTML builders for <c>RawCellHtml</c> cells. Everything that ends up in the markup goes
/// through <see cref="HtmlEncoder"/>: a raw cell is trusted HTML, and the values here
/// (DHCP hostnames, rule comments, peer names) come from clients and operators.
/// Pure functions, no state, no IO.
/// </summary>
public static class GridCell
{
    private static readonly HtmlEncoder Html = HtmlEncoder.Default;
    public const string Empty = "<span class=\"text-surface-fg-muted\">—</span>";

    public static string Encode(string? text) => Html.Encode(text ?? string.Empty);

    /// <summary>Monospace key/value chip (same look as the <c>_RuleChip</c> partial).</summary>
    public static string Chip(string label, string? value, string? title = null)
    {
        if (string.IsNullOrEmpty(value)) return Empty;
        var sb = new StringBuilder(160);
        sb.Append("<span class=\"nf-chip\"");
        if (!string.IsNullOrEmpty(title)) sb.Append(" title=\"").Append(Encode(title)).Append('"');
        sb.Append("><span class=\"nf-chip-k\">").Append(Encode(label))
          .Append("</span><span class=\"nf-chip-v\">").Append(Encode(value)).Append("</span></span>");
        return sb.ToString();
    }

    /// <summary>A plain monospace value (addresses, ports, marks).</summary>
    public static string Mono(string? text) =>
        string.IsNullOrEmpty(text) ? Empty : $"<span class=\"font-mono text-[12px]\">{Encode(text)}</span>";

    public static string Text(string? text) => string.IsNullOrWhiteSpace(text) ? Empty : Encode(text);

    public static string Muted(string? text) =>
        string.IsNullOrWhiteSpace(text) ? Empty : $"<span class=\"text-surface-fg-muted\">{Encode(text)}</span>";

    /// <summary>Primary line plus a muted second line (name + description).</summary>
    public static string TwoLine(string? primary, string? secondary)
    {
        if (string.IsNullOrWhiteSpace(secondary)) return Text(primary);
        return $"<div class=\"leading-tight\"><div class=\"font-medium\">{Text(primary)}</div><div class=\"text-xs text-surface-fg-muted truncate\">{Encode(secondary)}</div></div>";
    }

    public static string Badge(BadgeTone tone, string text) =>
        $"<span class=\"badge {ToneClass(tone)}\">{Encode(text)}</span>";

    /// <summary>A badge with a leading status dot (enabled/disabled, up/down).</summary>
    public static string Status(BadgeTone tone, string text) =>
        $"<span class=\"badge {ToneClass(tone)}\"><span class=\"nf-dot\"></span>{Encode(text)}</span>";

    public static string Enabled(bool enabled) =>
        enabled ? Status(BadgeTone.Success, "Enabled") : Status(BadgeTone.Muted, "Disabled");

    public static string Wrap(params string[] parts) =>
        $"<div class=\"flex items-center gap-1 flex-wrap\">{string.Concat(parts)}</div>";

    /// <summary>Relative time ("in 3 h 20 m", "5 m ago") with the absolute time as tooltip.</summary>
    public static string When(DateTime utc, DateTime nowUtc)
    {
        var local = utc.ToLocalTime().ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture);
        var delta = utc - nowUtc;
        var rel = Humanize(delta.Duration());
        var text = delta >= TimeSpan.Zero ? $"in {rel}" : $"{rel} ago";
        var soon = delta > TimeSpan.Zero && delta < TimeSpan.FromHours(1);
        var cls = soon ? "text-feedback-warning-fg" : "text-surface-fg-muted";
        return $"<span class=\"text-xs {cls}\" title=\"{Encode(local)}\">{Encode(text)}</span>";
    }

    public static string Humanize(TimeSpan span) => span.TotalMinutes < 1 ? $"{Math.Max(0, (int)span.TotalSeconds)} s"
        : span.TotalHours < 1 ? $"{(int)span.TotalMinutes} m"
        : span.TotalDays < 1 ? $"{(int)span.TotalHours} h {span.Minutes} m"
        : $"{(int)span.TotalDays} d {span.Hours} h";

    /// <summary>A ghost-button link that navigates the HOST page (<c>target="_top"</c>), out of the frame.</summary>
    public static string Link(string href, string label) =>
        $"<a class=\"btn btn-ghost btn-xs\" target=\"_top\" href=\"{Encode(href)}\">{Encode(label)}</a>";

    /// <summary>The trailing action cell: one ghost button per action, right-aligned.</summary>
    public static string Actions(params GridRowAction?[] actions) => Actions(links: [], actions);

    /// <summary>Navigation links (<see cref="Link"/>) followed by the action buttons, in one row.</summary>
    public static string Actions(IEnumerable<(string Href, string Label)> links, params GridRowAction?[] actions)
    {
        var sb = new StringBuilder(256);
        sb.Append("<div class=\"inline-flex items-center justify-end gap-1 w-full\">");
        foreach (var (href, label) in links) sb.Append(Link(href, label));
        foreach (var a in actions)
        {
            if (a is null) continue;
            sb.Append("<button type=\"button\" class=\"btn btn-ghost btn-xs");
            if (a.Danger) sb.Append(" text-feedback-danger-fg");
            sb.Append("\" data-nf-action=\"").Append(a.Kind == GridActionKind.Drawer ? "drawer" : "post")
              .Append("\" data-url=\"").Append(Encode(a.Url)).Append('"');
            if (a.DrawerTitle is { } dt) sb.Append(" data-title=\"").Append(Encode(dt)).Append('"');
            if (a.Tooltip is { } tip) sb.Append(" title=\"").Append(Encode(tip)).Append('"');
            if (a.Values is { Count: > 0 } vals) sb.Append(" data-vals=\"").Append(Encode(JsonSerializer.Serialize(vals))).Append('"');
            if (a.Confirm is { } c)
            {
                sb.Append(" data-confirm-title=\"").Append(Encode(c.Title))
                  .Append("\" data-confirm-message=\"").Append(Encode(c.Message))
                  .Append("\" data-confirm-label=\"").Append(Encode(c.ConfirmLabel))
                  .Append("\" data-confirm-level=\"").Append(Encode(c.Level)).Append('"');
            }
            sb.Append('>').Append(Encode(a.Label)).Append("</button>");
        }
        sb.Append("</div>");
        return sb.ToString();
    }

    private static string ToneClass(BadgeTone tone) => tone switch
    {
        BadgeTone.Accent => "badge-accent",
        BadgeTone.Success => "badge-success",
        BadgeTone.Warning => "badge-warning",
        BadgeTone.Danger => "badge-danger",
        BadgeTone.Info => "badge-info",
        _ => "badge-muted",
    };
}
