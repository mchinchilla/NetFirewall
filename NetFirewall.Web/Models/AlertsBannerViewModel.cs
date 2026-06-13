namespace NetFirewall.Web.Models;

/// <summary>
/// One active alert as the banner renders it. Flattened from the daemon's
/// SystemAlert wire shape so the partial stays free of service types.
/// </summary>
public sealed record ActiveAlertViewModel(
    string Severity,   // danger | warning | info
    string Title,
    string? Body,
    DateTime RaisedAt);

/// <summary>
/// Model for the <c>_AlertsBanner</c> partial — the currently-active system
/// alerts (today: VPN-down). Empty list → the partial renders nothing.
/// </summary>
public sealed class AlertsBannerViewModel
{
    public IReadOnlyList<ActiveAlertViewModel> Alerts { get; init; } = Array.Empty<ActiveAlertViewModel>();
}
