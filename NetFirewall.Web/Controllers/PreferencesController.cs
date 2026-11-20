using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Theming;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// Appearance persistence for the theme picker. The picker applies a change optimistically
/// (site.js, before the request leaves) and posts the axis it changed; this validates it against
/// the closed catalogues and rewrites the <c>nf_ui</c> cookie the layouts read before first paint.
/// The new look IS the success feedback; a refused value comes back as a toast.
/// </summary>
[Route("/preferences")]
public sealed class PreferencesController(IAppearanceProvider appearance) : Controller
{
    [HttpPost("appearance"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Appearance(
        [FromForm] string? mode, [FromForm] string? preset, [FromForm] string? sidebar, [FromForm] string? density,
        [FromForm] bool reset, CancellationToken ct)
    {
        var next = reset ? await appearance.GetDefaultsAsync(ct) : await appearance.GetAsync(ct);
        var changes = new (string Axis, string? Value)[] { ("mode", mode), ("preset", preset), ("sidebar", sidebar), ("density", density) };
        foreach (var (axis, value) in changes)
        {
            if (value is null) continue;
            if (!next.TryWith(axis, value, out var updated))
            {
                Response.StatusCode = StatusCodes.Status400BadRequest;
                return this.ToHtmxResponse(ServiceResponse<object>.Fail($"Unknown {axis} '{value}'."));
            }
            next = updated;
        }

        Response.Cookies.Append(Theming.Appearance.CookieName, next.ToCookie(), new CookieOptions
        {
            HttpOnly = true,
            IsEssential = true,
            SameSite = SameSiteMode.Lax,
            Secure = Request.IsHttps,
            MaxAge = TimeSpan.FromDays(365),
            Path = "/",
        });
        return NoContent();
    }
}
