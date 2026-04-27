using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Auth;
using NetFirewall.Web.Auth;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// Coverage for the cookie-backed auth handler. Each request hits the DB to
/// look up the session — that "DB is the source of truth" property is what
/// makes logout / revocation immediate (no waiting for cookie expiry), so
/// every branch here matters for security.
/// </summary>
public class SessionCookieAuthHandlerTests
{
    private readonly Mock<ISessionService> _sessions = new();
    private readonly Mock<IUserService> _users = new();

    /// <summary>
    /// Build a real <see cref="SessionCookieAuthHandler"/> wired to a fake
    /// <see cref="HttpContext"/>. Returns the handler + the context so tests
    /// can inspect Response after invoking AuthenticateAsync().
    /// </summary>
    private async Task<(SessionCookieAuthHandler handler, HttpContext ctx)> BuildHandlerAsync(string? cookieValue)
    {
        var optionsMonitor = new Mock<IOptionsMonitor<AuthenticationSchemeOptions>>();
        optionsMonitor.Setup(m => m.Get(It.IsAny<string>())).Returns(new AuthenticationSchemeOptions());

        var handler = new SessionCookieAuthHandler(
            optionsMonitor.Object,
            NullLoggerFactory.Instance,
            UrlEncoder.Default,
            _sessions.Object,
            _users.Object);

        var ctx = new DefaultHttpContext();
        if (cookieValue is not null)
            ctx.Request.Headers.Cookie = $"{SessionCookieAuthHandler.CookieName}={cookieValue}";

        var scheme = new AuthenticationScheme(
            SessionCookieAuthHandler.SchemeName, null, typeof(SessionCookieAuthHandler));
        await handler.InitializeAsync(scheme, ctx);
        return (handler, ctx);
    }

    private static UserSession FakeSession(Guid userId, string level = AuthLevels.Basic, DateTimeOffset? elevatedUntil = null) => new()
    {
        Id = Guid.NewGuid(),
        UserId = userId,
        TokenHash = "irrelevant",
        AuthLevel = level,
        ElevatedUntil = elevatedUntil,
        CreatedAt = DateTimeOffset.UtcNow,
        ExpiresAt = DateTimeOffset.UtcNow.AddHours(1),
        LastSeenAt = DateTimeOffset.UtcNow
    };

    private static User FakeUser(Guid id, bool active = true, string role = UserRoles.Operator) => new()
    {
        Id = id,
        Username = "alice",
        PasswordHash = "x",
        Role = role,
        IsActive = active
    };

    // ── HandleAuthenticateAsync ────────────────────────────────────────

    [Fact]
    public async Task NoCookie_ReturnsNoResult_DoesNotHitSessionService()
    {
        var (handler, _) = await BuildHandlerAsync(cookieValue: null);

        var result = await handler.AuthenticateAsync();

        Assert.True(result.None);
        _sessions.Verify(s => s.ValidateAsync(It.IsAny<string>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task EmptyCookieValue_ReturnsNoResult()
    {
        var (handler, _) = await BuildHandlerAsync(cookieValue: "");

        var result = await handler.AuthenticateAsync();

        Assert.True(result.None);
    }

    [Fact]
    public async Task InvalidToken_ReturnsNoResult_AndDeletesCookie()
    {
        _sessions.Setup(s => s.ValidateAsync("bogus", It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
                 .ReturnsAsync((UserSession?)null);
        var (handler, ctx) = await BuildHandlerAsync(cookieValue: "bogus");

        var result = await handler.AuthenticateAsync();

        Assert.True(result.None);
        // Set-Cookie with an expired Expires effectively deletes the cookie.
        var setCookie = ctx.Response.Headers["Set-Cookie"].ToString();
        Assert.Contains(SessionCookieAuthHandler.CookieName, setCookie);
    }

    [Fact]
    public async Task ValidationThrows_ReturnsFail()
    {
        _sessions.Setup(s => s.ValidateAsync(It.IsAny<string>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
                 .ThrowsAsync(new InvalidOperationException("db down"));
        var (handler, _) = await BuildHandlerAsync(cookieValue: "any");

        var result = await handler.AuthenticateAsync();

        Assert.False(result.Succeeded);
        Assert.NotNull(result.Failure);
        Assert.Contains("Session lookup failed", result.Failure!.Message);
    }

    [Fact]
    public async Task ValidSession_ButUserMissing_RevokesSession_AndClearsCookie()
    {
        // The user was deleted between login and this request — revoke the
        // dangling session and don't hand the request a principal.
        var session = FakeSession(Guid.NewGuid());
        _sessions.Setup(s => s.ValidateAsync(It.IsAny<string>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
                 .ReturnsAsync(session);
        _users.Setup(u => u.GetByIdAsync(session.UserId, It.IsAny<CancellationToken>()))
              .ReturnsAsync((User?)null);

        var (handler, ctx) = await BuildHandlerAsync(cookieValue: "valid-token");
        var result = await handler.AuthenticateAsync();

        Assert.True(result.None);
        _sessions.Verify(s => s.RevokeAsync(session.Id, It.IsAny<CancellationToken>()), Times.Once);
        Assert.Contains(SessionCookieAuthHandler.CookieName, ctx.Response.Headers["Set-Cookie"].ToString());
    }

    [Fact]
    public async Task ValidSession_ButUserDisabled_RevokesSession_AndClearsCookie()
    {
        var session = FakeSession(Guid.NewGuid());
        _sessions.Setup(s => s.ValidateAsync(It.IsAny<string>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
                 .ReturnsAsync(session);
        _users.Setup(u => u.GetByIdAsync(session.UserId, It.IsAny<CancellationToken>()))
              .ReturnsAsync(FakeUser(session.UserId, active: false));

        var (handler, ctx) = await BuildHandlerAsync(cookieValue: "valid-token");
        var result = await handler.AuthenticateAsync();

        Assert.True(result.None);
        _sessions.Verify(s => s.RevokeAsync(session.Id, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ValidSessionAndUser_BasicLevel_PrincipalCarriesAllClaims()
    {
        var uid = Guid.NewGuid();
        var session = FakeSession(uid);
        _sessions.Setup(s => s.ValidateAsync(It.IsAny<string>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
                 .ReturnsAsync(session);
        _users.Setup(u => u.GetByIdAsync(uid, It.IsAny<CancellationToken>()))
              .ReturnsAsync(FakeUser(uid, role: UserRoles.Operator));

        var (handler, _) = await BuildHandlerAsync(cookieValue: "valid-token");
        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        var principal = result.Principal!;
        Assert.Equal(uid.ToString(), principal.FindFirstValue(ClaimTypes.NameIdentifier));
        Assert.Equal("alice", principal.FindFirstValue(ClaimTypes.Name));
        Assert.Equal(UserRoles.Operator, principal.FindFirstValue(ClaimTypes.Role));
        Assert.Equal(AuthLevels.Basic, principal.FindFirstValue(SessionCookieAuthHandler.AuthLevelClaim));
        Assert.Equal(session.Id.ToString(), principal.FindFirstValue(SessionCookieAuthHandler.SessionIdClaim));
    }

    [Fact]
    public async Task ValidSession_Elevated_AndStillInWindow_ClaimsAuthLevelElevated()
    {
        var uid = Guid.NewGuid();
        var session = FakeSession(uid, level: AuthLevels.Elevated, elevatedUntil: DateTimeOffset.UtcNow.AddMinutes(5));
        _sessions.Setup(s => s.ValidateAsync(It.IsAny<string>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
                 .ReturnsAsync(session);
        _users.Setup(u => u.GetByIdAsync(uid, It.IsAny<CancellationToken>()))
              .ReturnsAsync(FakeUser(uid));

        var (handler, _) = await BuildHandlerAsync(cookieValue: "valid-token");
        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.Equal(AuthLevels.Elevated, result.Principal!.FindFirstValue(SessionCookieAuthHandler.AuthLevelClaim));
    }

    [Fact]
    public async Task ValidSession_ElevatedExpired_ClaimsBackToBasic()
    {
        // The session row is still elevated, but the elevation window passed.
        // IsElevated(now) returns false, so the claim downgrades to basic and
        // RequireElevated guards see "not elevated" — the user must step up again.
        var uid = Guid.NewGuid();
        var session = FakeSession(uid, level: AuthLevels.Elevated, elevatedUntil: DateTimeOffset.UtcNow.AddMinutes(-1));
        _sessions.Setup(s => s.ValidateAsync(It.IsAny<string>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
                 .ReturnsAsync(session);
        _users.Setup(u => u.GetByIdAsync(uid, It.IsAny<CancellationToken>()))
              .ReturnsAsync(FakeUser(uid));

        var (handler, _) = await BuildHandlerAsync(cookieValue: "valid-token");
        var result = await handler.AuthenticateAsync();

        Assert.True(result.Succeeded);
        Assert.Equal(AuthLevels.Basic, result.Principal!.FindFirstValue(SessionCookieAuthHandler.AuthLevelClaim));
    }

    // ── HandleChallengeAsync ───────────────────────────────────────────

    [Fact]
    public async Task Challenge_NormalRequest_RedirectsToLoginWithReturnUrl()
    {
        var (handler, ctx) = await BuildHandlerAsync(cookieValue: null);
        ctx.Request.Path = "/dashboard";
        ctx.Request.QueryString = new QueryString("?x=1");

        await handler.ChallengeAsync(properties: null);

        Assert.Equal(302, ctx.Response.StatusCode);
        Assert.Contains("/login?returnUrl=", ctx.Response.Headers.Location.ToString());
        Assert.Contains("%2Fdashboard", ctx.Response.Headers.Location.ToString());
    }

    [Fact]
    public async Task Challenge_HtmxRequest_Returns401_WithHxRedirectHeader()
    {
        var (handler, ctx) = await BuildHandlerAsync(cookieValue: null);
        ctx.Request.Headers["HX-Request"] = "true";
        ctx.Request.Path = "/firewall/rules";

        await handler.ChallengeAsync(properties: null);

        Assert.Equal(401, ctx.Response.StatusCode);
        var hxRedirect = ctx.Response.Headers["HX-Redirect"].ToString();
        Assert.Contains("/login?returnUrl=", hxRedirect);
        Assert.Contains("%2Ffirewall%2Frules", hxRedirect);
    }

    // ── HandleForbiddenAsync ───────────────────────────────────────────

    [Fact]
    public async Task Forbid_Returns403_NoBodyOrRedirect()
    {
        var (handler, ctx) = await BuildHandlerAsync(cookieValue: null);

        await handler.ForbidAsync(properties: null);

        Assert.Equal(403, ctx.Response.StatusCode);
        Assert.Empty(ctx.Response.Headers.Location.ToString());
    }

    // ── BuildCookieOptions sanity ──────────────────────────────────────

    [Fact]
    public void BuildCookieOptions_ProducesHostPrefixCompatibleAttributes()
    {
        var opts = SessionCookieAuthHandler.BuildCookieOptions(DateTimeOffset.UtcNow.AddHours(8));

        Assert.True(opts.HttpOnly);
        Assert.True(opts.Secure);                      // __Host- prefix requires Secure
        Assert.Equal(SameSiteMode.Strict, opts.SameSite);
        Assert.Equal("/", opts.Path);                  // __Host- prefix requires Path=/
        Assert.Null(opts.Domain);                      // __Host- prefix forbids Domain
        Assert.True(opts.IsEssential);
    }
}
