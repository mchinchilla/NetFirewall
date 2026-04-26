using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;

namespace NetFirewall.Web.Auth;

/// <summary>
/// Carries the "you proved your password — now do TOTP" state between the
/// /login → /login/totp and /login → /account/totp/enroll redirects.
///
/// Backed by a short-lived signed cookie (DataProtection) instead of TempData
/// because TempData via cookie can silently drop across cross-controller
/// redirects when other middleware writes the response. The cookie uses the
/// __Host- prefix (Secure + Path=/ + no Domain), SameSite=Strict, HttpOnly,
/// and a 10-minute hard expiry — long enough to enroll TOTP, short enough to
/// not leave a half-auth artifact lying around.
/// </summary>
public interface IPendingAuthTicket
{
    void Issue(Guid userId, string? returnUrl = null, byte[]? enrollSecret = null);
    bool TryRead(out Guid userId, out string? returnUrl, out byte[]? enrollSecret);
    void Clear();
}

public sealed class PendingAuthTicket : IPendingAuthTicket
{
    public const string CookieName = "__Host-NetFw.Pending";
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);

    private readonly IHttpContextAccessor _http;
    private readonly IDataProtector _protector;

    public PendingAuthTicket(IHttpContextAccessor http, IDataProtectionProvider dpp)
    {
        _http = http;
        _protector = dpp.CreateProtector("NetFirewall.PendingAuth.v1");
    }

    public void Issue(Guid userId, string? returnUrl = null, byte[]? enrollSecret = null)
    {
        var ctx = _http.HttpContext ?? throw new InvalidOperationException("No HttpContext.");
        var expiresAt = DateTimeOffset.UtcNow + Lifetime;
        var payload = new Payload(
            userId,
            expiresAt.ToUnixTimeSeconds(),
            string.IsNullOrEmpty(returnUrl) ? null : returnUrl,
            enrollSecret is null ? null : Convert.ToBase64String(enrollSecret));
        var token = _protector.Protect(JsonSerializer.Serialize(payload));
        ctx.Response.Cookies.Append(CookieName, token, BuildCookieOptions(expiresAt));
    }

    public bool TryRead(out Guid userId, out string? returnUrl, out byte[]? enrollSecret)
    {
        userId = Guid.Empty;
        returnUrl = null;
        enrollSecret = null;

        var ctx = _http.HttpContext;
        if (ctx is null) return false;
        if (!ctx.Request.Cookies.TryGetValue(CookieName, out var token) || string.IsNullOrEmpty(token))
            return false;

        try
        {
            var json = _protector.Unprotect(token);
            var payload = JsonSerializer.Deserialize<Payload>(json);
            if (payload is null) return false;
            if (DateTimeOffset.FromUnixTimeSeconds(payload.E) < DateTimeOffset.UtcNow) return false;

            userId = payload.U;
            returnUrl = payload.R;
            enrollSecret = string.IsNullOrEmpty(payload.S) ? null : Convert.FromBase64String(payload.S);
            return true;
        }
        catch (CryptographicException) { return false; }
        catch (JsonException) { return false; }
        catch (FormatException) { return false; }
    }

    public void Clear()
    {
        var ctx = _http.HttpContext;
        if (ctx is null) return;
        ctx.Response.Cookies.Delete(CookieName, BuildCookieOptions(DateTimeOffset.UtcNow));
    }

    private static CookieOptions BuildCookieOptions(DateTimeOffset expiresAt) => new()
    {
        HttpOnly = true,
        Secure = true,                 // __Host- requires Secure
        SameSite = SameSiteMode.Strict,
        Path = "/",                    // __Host- requires Path=/
        Expires = expiresAt,
        IsEssential = true,
    };

    // Short field names to keep the encrypted cookie compact.
    private sealed record Payload(Guid U, long E, string? R, string? S);
}
