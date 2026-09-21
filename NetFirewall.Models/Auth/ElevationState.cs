namespace NetFirewall.Models.Auth;

/// <summary>
/// Whether the caller's session still counts as TOTP-elevated.
///
/// Elevation expires on a timer, so a control that leaves the page (a file
/// download, for instance) cannot assume the level it had when the page was
/// rendered. Such a control asks first, and opens the step-up modal instead of
/// navigating into a 401 the browser would render as raw JSON.
/// </summary>
/// <param name="Elevated">True while the session is elevated.</param>
public sealed record ElevationState(bool Elevated);
