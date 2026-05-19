namespace NetFirewall.Web.Models.Shared;

/// <summary>
/// Tells <c>_LoadingOverlay.cshtml</c> how to render itself. Three variants
/// cover every load case in the app — see the partial for usage examples.
/// </summary>
public sealed class LoadingOverlayModel
{
    /// <summary>
    /// Text shown next to the spinner. Empty string hides the label so the
    /// spinner stands alone (good for very small surfaces).
    /// </summary>
    public string Label { get; init; } = "Loading…";

    /// <summary>
    /// <list type="bullet">
    ///   <item><c>Overlay</c> (default) — absolute, blurs the parent. Use
    ///         inside a <c>.loading-host</c> wrapper for HTMX-swapped regions
    ///         that already have visible content underneath.</item>
    ///   <item><c>Placeholder</c> — inline, no blur. Use as the initial
    ///         contents of an empty HTMX container (replaces the bare
    ///         <c>&lt;div&gt;Loading…&lt;/div&gt;</c> across the app).</item>
    /// </list>
    /// </summary>
    public LoadingOverlayVariant Variant { get; init; } = LoadingOverlayVariant.Overlay;

    /// <summary>Spinner size. Sm fits inside buttons; Md is the default; Lg
    /// fits full-page or large card placeholders.</summary>
    public LoadingOverlaySize Size { get; init; } = LoadingOverlaySize.Md;

    /// <summary>
    /// When true, the overlay is rendered already-visible (placeholder mode
    /// uses this for the first paint; for overlay mode it's the rare case
    /// where the parent doesn't yet have the <c>htmx-request</c> class but
    /// you still want it on).
    /// </summary>
    public bool ShowInitially { get; init; }
}

public enum LoadingOverlayVariant { Overlay, Placeholder }
public enum LoadingOverlaySize     { Sm, Md, Lg }
