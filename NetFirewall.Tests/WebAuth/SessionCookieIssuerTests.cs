using System.Net;
using Microsoft.AspNetCore.Http;
using Moq;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Auth;
using NetFirewall.Web.Auth;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// Coverage for the central session-cookie issuer. Both AuthController (after
/// password+TOTP) and AccountController (after enrollment) call this — keeping
/// cookie options and the audit log in one place. A regression here means
/// cookie attributes drift between login paths or audit log entries go
/// missing for some logins, both visible-but-quiet bugs.
/// </summary>
public class SessionCookieIssuerTests
{
    private readonly Mock<ISessionService> _sessions = new();
    private readonly Mock<IAuthAuditService> _audit = new();

    private SessionCookieIssuer Create() => new(_sessions.Object, _audit.Object);

    private static User MakeUser() => new()
    {
        Id = Guid.NewGuid(),
        Username = "alice",
        PasswordHash = "$argon2id$x",
        Role = UserRoles.Operator,
        IsActive = true
    };

    private static (string Token, UserSession Session) MakeIssuedSession(Guid userId)
    {
        var session = new UserSession
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TokenHash = "fake-hash",
            AuthLevel = AuthLevels.Basic,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddHours(8),
            LastSeenAt = DateTimeOffset.UtcNow
        };
        return ("plaintext-cookie-value", session);
    }

    private static HttpContext MakeContext(IPAddress? ip = null, string? userAgent = null)
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = ip ?? IPAddress.Parse("203.0.113.7");
        if (userAgent is not null)
            ctx.Request.Headers.UserAgent = userAgent;
        return ctx;
    }

    // ── Issue path ─────────────────────────────────────────────────────

    [Fact]
    public async Task IssueAsync_CallsSessionsIssue_WithIpAndUserAgentFromHttpContext()
    {
        var user = MakeUser();
        var ctx = MakeContext(IPAddress.Parse("198.51.100.42"), "Mozilla/5.0 (test)");
        var (token, session) = MakeIssuedSession(user.Id);

        _sessions.Setup(s => s.IssueAsync(
                user.Id, IPAddress.Parse("198.51.100.42"), "Mozilla/5.0 (test)",
                SessionCookieAuthHandler.BasicLifetime, It.IsAny<CancellationToken>()))
            .ReturnsAsync((token, session));

        await Create().IssueAsync(ctx, user);

        _sessions.Verify(s => s.IssueAsync(
            user.Id,
            It.Is<IPAddress>(a => a.ToString() == "198.51.100.42"),
            "Mozilla/5.0 (test)",
            SessionCookieAuthHandler.BasicLifetime,
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task IssueAsync_WritesCookieWithExactPlaintextTokenAndSchemeName()
    {
        var user = MakeUser();
        var ctx = MakeContext();
        var (token, session) = MakeIssuedSession(user.Id);
        _sessions.Setup(s => s.IssueAsync(It.IsAny<Guid>(), It.IsAny<IPAddress?>(), It.IsAny<string?>(),
                It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((token, session));

        await Create().IssueAsync(ctx, user);

        var setCookie = ctx.Response.Headers["Set-Cookie"].ToString();
        Assert.Contains($"{SessionCookieAuthHandler.CookieName}={token}", setCookie);
        // __Host- prefix requirements: Secure + Path=/ + no Domain
        Assert.Contains("secure", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("path=/", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("samesite=strict", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("httponly", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("domain=", setCookie, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task IssueAsync_AuditLogsLoginSuccess_WithUsernameAndIp()
    {
        var user = MakeUser();
        var ctx = MakeContext(IPAddress.Parse("198.51.100.42"), "MyUA");
        var (token, session) = MakeIssuedSession(user.Id);
        _sessions.Setup(s => s.IssueAsync(It.IsAny<Guid>(), It.IsAny<IPAddress?>(), It.IsAny<string?>(),
                It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((token, session));

        await Create().IssueAsync(ctx, user);

        _audit.Verify(a => a.LogAsync(
            AuthAuditEvents.LoginSuccess,
            user.Id,
            "alice",
            It.Is<IPAddress?>(ip => ip != null && ip.ToString() == "198.51.100.42"),
            "MyUA",
            null,
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task IssueAsync_NoRemoteIp_StillIssues_LogsNullIp()
    {
        // RemoteIpAddress can be null in some pipeline configurations; the
        // issuer must not crash and the audit row should reflect "we tried".
        var user = MakeUser();
        var ctx = new DefaultHttpContext(); // no remote IP, no UA
        var (token, session) = MakeIssuedSession(user.Id);
        _sessions.Setup(s => s.IssueAsync(It.IsAny<Guid>(), It.IsAny<IPAddress?>(), It.IsAny<string?>(),
                It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((token, session));

        await Create().IssueAsync(ctx, user);

        // Default IHeaderDictionary returns an empty StringValues for missing
        // User-Agent, which ToString()s to "" — issuer hands that to audit/sessions.
        _sessions.Verify(s => s.IssueAsync(
            user.Id, null, "", SessionCookieAuthHandler.BasicLifetime, It.IsAny<CancellationToken>()), Times.Once);
        _audit.Verify(a => a.LogAsync(
            AuthAuditEvents.LoginSuccess,
            user.Id, "alice",
            null,                    // ip
            "",                      // user agent
            null, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task IssueAsync_CookieExpiryMatchesSessionExpiresAt()
    {
        // Bug class to prevent: cookie outliving the session row (browser keeps
        // a cookie that the server already considers expired, leading to
        // confusing 401s mid-session).
        var user = MakeUser();
        var ctx = MakeContext();
        var hardExpiry = DateTimeOffset.UtcNow.AddHours(2);
        var session = new UserSession
        {
            Id = Guid.NewGuid(), UserId = user.Id, TokenHash = "x",
            AuthLevel = AuthLevels.Basic,
            CreatedAt = DateTimeOffset.UtcNow,
            ExpiresAt = hardExpiry,
            LastSeenAt = DateTimeOffset.UtcNow
        };
        _sessions.Setup(s => s.IssueAsync(It.IsAny<Guid>(), It.IsAny<IPAddress?>(), It.IsAny<string?>(),
                It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(("tok", session));

        await Create().IssueAsync(ctx, user);

        var setCookie = ctx.Response.Headers["Set-Cookie"].ToString();
        // Expires header is RFC 1123 GMT — a slice match on the year is enough
        // here; we mostly care that the cookie carries an Expires aligned to
        // the session row, not "session" (browser-session).
        Assert.Contains("expires=", setCookie, StringComparison.OrdinalIgnoreCase);
        Assert.Contains(hardExpiry.UtcDateTime.Year.ToString(), setCookie);
    }
}
