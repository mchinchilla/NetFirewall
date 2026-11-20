namespace NetFirewall.Web.Theming;

/// <summary>The current request's appearance: the user's cookie over the configured defaults.</summary>
public interface IAppearanceProvider
{
    Task<Appearance> GetAsync(CancellationToken ct = default);

    /// <summary>The site defaults (Settings → Appearance), used for anonymous pages and the Reset button.</summary>
    Task<Appearance> GetDefaultsAsync(CancellationToken ct = default);
}
