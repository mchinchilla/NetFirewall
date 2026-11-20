namespace NetFirewall.Web.Models.Shared;

/// <summary>
/// A miniature window drawn with the real tokens (no images, no JS). <see cref="Scheme"/> pins
/// light/dark (<c>scheme-light</c> / <c>scheme-dark</c>) for the Mode tiles; null follows the page.
/// <see cref="Preset"/> pins the accent for the Accent tiles; null follows the page.
/// </summary>
public sealed record ThemeThumbModel(string? Scheme = null, string? Preset = null);
