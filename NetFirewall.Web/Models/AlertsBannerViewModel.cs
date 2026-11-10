namespace NetFirewall.Web.Models;

/// <summary>
/// One active alert as the banner renders it. Flattened from the daemon's
/// SystemAlert wire shape so the partial stays free of service types.
/// <paramref name="Key"/> and <paramref name="Source"/> let the client detect
/// newly-appeared / disappeared alerts (for the audible alarm) without DOM
/// diffing.
/// </summary>
public sealed record ActiveAlertViewModel(
    string Severity,   // danger | warning | info
    string Title,
    string? Body,
    DateTime RaisedAt,
    string Key = "",     // stable dedupe key, e.g. "wan:down:<id>"
    string Source = "",  // vpn | wan | …
    long Id = 0);        // system_alerts id — what the dismiss button posts

/// <summary>
/// Model for the <c>_AlertsBanner</c> partial — the currently-active system
/// alerts (today: VPN-down). Empty list → the partial renders nothing.
/// </summary>
public sealed class AlertsBannerViewModel
{
    public IReadOnlyList<ActiveAlertViewModel> Alerts { get; init; } = Array.Empty<ActiveAlertViewModel>();

    /// <summary>Whether to render the dismiss button (Admin / Operator only).</summary>
    public bool CanDismiss { get; init; }
}

/// <summary>
/// One alert row for the notifications dropdown and the full history page.
/// Includes resolved state + source so the UI can style and group them.
/// </summary>
public sealed record NotificationItemViewModel(
    string Severity,    // danger | warning | info
    string Source,      // vpn | wan | …
    string Title,
    string? Body,
    DateTime RaisedAt,
    DateTime? ResolvedAt,
    DateTime? DismissedAt = null)
{
    public bool IsActive => ResolvedAt is null && DismissedAt is null;

    /// <summary>Why it is no longer active, for the feed's status label.</summary>
    public string InactiveLabel => ResolvedAt is null ? "dismissed" : "resolved";
}

/// <summary>
/// Model for the notifications dropdown fragment and the activity history page.
/// </summary>
public sealed class NotificationsViewModel
{
    public IReadOnlyList<NotificationItemViewModel> Items { get; init; } = Array.Empty<NotificationItemViewModel>();

    /// <summary>Count of unresolved (active) alerts — drives the unread badge.</summary>
    public int ActiveCount => Items.Count(i => i.IsActive);
}
