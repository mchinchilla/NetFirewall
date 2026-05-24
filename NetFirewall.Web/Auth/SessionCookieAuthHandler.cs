using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Auth;

namespace NetFirewall.Web.Auth;

/// <summary>
/// Cookie-backed auth handler. The cookie value is the opaque session token —
/// not encrypted claims — so logout / revocation is immediate (the DB row
/// becomes the source of truth on every request, no waiting for cookie expiry).
/// Sliding window for basic sessions, hard cap for elevated, both enforced in
/// <see cref="ISessionService.ValidateAsync"/>.
/// </summary>
public sealed class SessionCookieAuthHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public const string SchemeName = "SessionCookie";

    /// <summary>__Host- prefix forces Secure + Path=/ + no Domain at the browser level.</summary>
    public const string CookieName = "__Host-NetFw.Sid";

    /// <summary>Inactivity window for basic sessions; slides forward on each request.</summary>
    public static readonly TimeSpan BasicLifetime = TimeSpan.FromHours(8);

    /// <summary>Custom claim carrying basic / elevated.</summary>
    public const string AuthLevelClaim = "auth_level";

    /// <summary>Session row id (so logout / revoke knows what to invalidate).</summary>
    public const string SessionIdClaim = "session_id";

    private readonly ISessionService _sessions;
    private readonly IUserService _users;

    public SessionCookieAuthHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISessionService sessions,
        IUserService users)
        : base(options, logger, encoder)
    {
        _sessions = sessions;
        _users = users;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Cookies.TryGetValue(CookieName, out var token) || string.IsNullOrEmpty(token))
            return AuthenticateResult.NoResult();

        UserSession? session;
        try
        {
            session = await _sessions.ValidateAsync(token, BasicLifetime, Context.RequestAborted);
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Session lookup failed");
            return AuthenticateResult.Fail("Session lookup failed.");
        }

        if (session is null)
        {
            // Stale or revoked cookie — clear it so the browser stops sending it.
            Response.Cookies.Delete(CookieName);
            return AuthenticateResult.NoResult();
        }

        var user = await _users.GetByIdAsync(session.UserId, Context.RequestAborted);
        if (user is null || !user.IsActive)
        {
            await _sessions.RevokeAsync(session.Id, Context.RequestAborted);
            Response.Cookies.Delete(CookieName);
            return AuthenticateResult.NoResult();
        }

        var now = DateTimeOffset.UtcNow;
        var elevated = session.IsElevated(now);

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim(AuthLevelClaim, elevated ? AuthLevels.Elevated : AuthLevels.Basic),
            new Claim(SessionIdClaim, session.Id.ToString())
        };

        var identity = new ClaimsIdentity(claims, SchemeName, ClaimTypes.Name, ClaimTypes.Role);
        var principal = new ClaimsPrincipal(identity);
        var ticket = new AuthenticationTicket(principal, SchemeName);
        return AuthenticateResult.Success(ticket);
    }

    /// <summary>Unauthenticated access → redirect to /login (or 401 for HTMX).</summary>
    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var returnUrl = ResolveReturnUrl();

        if (Request.Headers.ContainsKey("HX-Request"))
        {
            // HTMX: 401 + HX-Redirect so the browser navigates instead of swapping a 401 body.
            Response.StatusCode = 401;
            Response.Headers["HX-Redirect"] = $"/login?returnUrl={Uri.EscapeDataString(returnUrl)}";
            return Task.CompletedTask;
        }

        Response.Redirect($"/login?returnUrl={Uri.EscapeDataString(returnUrl)}");
        return Task.CompletedTask;
    }

    /// <summary>
    /// Resolves the URL the user should land on after re-authenticating.
    /// HTMX requests: trust ONLY HX-Current-URL (the page in the browser);
    /// Request.Path is the polled partial and would render layout-less if used.
    /// Non-HTMX requests: use Request.Path, but also fetch() calls from
    /// Alpine helpers (no HTMX headers) can hit JSON-only endpoints — so
    /// every candidate flows through <see cref="ReturnUrlGuard.Sanitize"/>,
    /// which downgrades known partial / JSON paths to "/".
    /// </summary>
    private string ResolveReturnUrl()
    {
        if (Request.Headers.ContainsKey("HX-Request"))
        {
            var currentUrl = Request.Headers["HX-Current-URL"].ToString();
            if (!string.IsNullOrEmpty(currentUrl)
                && Uri.TryCreate(currentUrl, UriKind.Absolute, out var uri)
                && string.Equals(uri.Host, Request.Host.Host, StringComparison.OrdinalIgnoreCase))
            {
                return ReturnUrlGuard.Sanitize(uri.PathAndQuery);
            }
            return "/";
        }

        return ReturnUrlGuard.Sanitize(Request.Path + Request.QueryString);
    }

    /// <summary>Authenticated but lacks the required role → 403.</summary>
    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        Response.StatusCode = 403;
        return Task.CompletedTask;
    }

    /// <summary>Cookie attributes used at sign-in. Centralised so issue + delete agree.</summary>
    public static CookieOptions BuildCookieOptions(DateTimeOffset expiresAt) => new()
    {
        HttpOnly = true,
        Secure = true,            // __Host- prefix REQUIRES Secure
        SameSite = SameSiteMode.Strict,
        Path = "/",               // __Host- prefix REQUIRES Path=/
        // No Domain — __Host- prefix forbids it
        Expires = expiresAt,
        IsEssential = true
    };
}
