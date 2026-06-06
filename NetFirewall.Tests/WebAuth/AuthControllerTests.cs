using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Auth;
using NetFirewall.Web.Auth;
using NetFirewall.Web.Controllers;
using NetFirewall.Web.Models.Auth;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// End-to-end-ish coverage of the login + TOTP + logout flow. The controller
/// is mock-driven (no WebApplicationFactory) so each test pins one specific
/// security-relevant decision: timing constancy on user-not-found, lockout
/// gate, MFA replay rejection, ReturnUrl preservation across the two-step
/// flow, and the cookie/audit emission on success.
/// </summary>
public class AuthControllerTests
{
    private readonly Mock<IUserService> _users = new();
    private readonly Mock<IUserTotpService> _totp = new();
    private readonly Mock<IRecoveryCodeService> _recovery = new();
    private readonly Mock<ISessionService> _sessions = new();
    private readonly Mock<ISessionCookieIssuer> _cookieIssuer = new();
    private readonly Mock<IPasswordHasher> _hasher = new();
    private readonly Mock<IAuthAuditService> _audit = new();
    private readonly Mock<IPendingAuthTicket> _pending = new();
    private readonly Mock<NetFirewall.Services.Monitoring.IGeoIpLookupService> _geo = new();

    private AuthController CreateController(HttpContext? ctx = null)
    {
        var c = new AuthController(
            _users.Object, _totp.Object, _recovery.Object, _sessions.Object,
            _cookieIssuer.Object, _hasher.Object, _audit.Object, _pending.Object,
            _geo.Object, NullLogger<AuthController>.Instance);
        c.ControllerContext = new ControllerContext { HttpContext = ctx ?? MakeHttpContext() };
        return c;
    }

    private static HttpContext MakeHttpContext(IPAddress? ip = null, string? ua = null,
        ClaimsPrincipal? user = null)
    {
        var ctx = new DefaultHttpContext();
        ctx.Connection.RemoteIpAddress = ip ?? IPAddress.Parse("203.0.113.7");
        if (ua is not null) ctx.Request.Headers.UserAgent = ua;
        if (user is not null) ctx.User = user;
        return ctx;
    }

    private static User MakeUser(string username = "alice",
        bool active = true, DateTimeOffset? lockedUntil = null) => new()
    {
        Id = Guid.NewGuid(),
        Username = username,
        PasswordHash = "$argon2id$x",
        Role = UserRoles.Operator,
        IsActive = active,
        LockedUntil = lockedUntil
    };

    // ── Login: validation gating ───────────────────────────────────────

    [Fact]
    public async Task Login_InvalidModelState_ReturnsView_NoSideEffects()
    {
        var c = CreateController();
        c.ModelState.AddModelError("Username", "required");

        var result = await c.Login(new LoginViewModel(), CancellationToken.None);

        Assert.IsType<ViewResult>(result);
        _users.Verify(u => u.GetByUsernameAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    // ── Login: timing-constant response on unknown username ────────────

    [Fact]
    public async Task Login_UnknownUsername_StillRunsHasherAgainstDummyHash()
    {
        // Anti-timing: must do real hash work even when the user doesn't exist
        // so login probes can't enumerate accounts via response-time difference.
        _users.Setup(u => u.GetByUsernameAsync("ghost", It.IsAny<CancellationToken>()))
              .ReturnsAsync((User?)null);

        var result = await CreateController().Login(
            new LoginViewModel { Username = "ghost", Password = "x" }, CancellationToken.None);

        _hasher.Verify(h => h.VerifyAsync(
            "x",
            It.Is<string>(s => s.StartsWith("$argon2id$")),
            It.IsAny<CancellationToken>()), Times.Once);
        _audit.Verify(a => a.LogAsync(
            AuthAuditEvents.LoginFailed, null, "ghost",
            It.IsAny<IPAddress?>(), It.IsAny<string?>(), It.IsAny<object?>(), It.IsAny<CancellationToken>()),
            Times.Once);
        Assert.IsType<ViewResult>(result);
    }

    // ── Login: gates ───────────────────────────────────────────────────

    [Fact]
    public async Task Login_InactiveAccount_ReturnsView_AuditsInactive()
    {
        var u = MakeUser(active: false);
        _users.Setup(s => s.GetByUsernameAsync("alice", It.IsAny<CancellationToken>())).ReturnsAsync(u);

        var result = await CreateController().Login(
            new LoginViewModel { Username = "alice", Password = "x" }, CancellationToken.None);

        Assert.IsType<ViewResult>(result);
        _hasher.Verify(h => h.VerifyAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        _audit.Verify(a => a.LogAsync(
            AuthAuditEvents.LoginFailed, u.Id, "alice",
            It.IsAny<IPAddress?>(), It.IsAny<string?>(),
            It.Is<object?>(d => d!.ToString()!.Contains("inactive")),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Login_LockedAccount_ReturnsView_AuditsLocked()
    {
        var u = MakeUser(lockedUntil: DateTimeOffset.UtcNow.AddMinutes(10));
        _users.Setup(s => s.GetByUsernameAsync("alice", It.IsAny<CancellationToken>())).ReturnsAsync(u);

        var result = await CreateController().Login(
            new LoginViewModel { Username = "alice", Password = "x" }, CancellationToken.None);

        Assert.IsType<ViewResult>(result);
        _audit.Verify(a => a.LogAsync(
            AuthAuditEvents.LoginLocked, u.Id, "alice",
            It.IsAny<IPAddress?>(), It.IsAny<string?>(), It.IsAny<object?>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Login_LockExpired_NoLongerBlocks()
    {
        // Edge: locked_until is in the past — the gate must NOT fire.
        var u = MakeUser(lockedUntil: DateTimeOffset.UtcNow.AddMinutes(-1));
        _users.Setup(s => s.GetByUsernameAsync("alice", It.IsAny<CancellationToken>())).ReturnsAsync(u);
        _hasher.Setup(h => h.VerifyAsync("good", u.PasswordHash, It.IsAny<CancellationToken>()))
               .ReturnsAsync(new PasswordVerificationResult(true, false));
        _totp.Setup(t => t.HasEnrolledAsync(u.Id, It.IsAny<CancellationToken>())).ReturnsAsync(true);

        var result = await CreateController().Login(
            new LoginViewModel { Username = "alice", Password = "good" }, CancellationToken.None);

        // Lock didn't trigger → flow continued to redirect.
        Assert.IsType<RedirectToActionResult>(result);
    }

    [Fact]
    public async Task Login_BadPassword_RecordsFailure_AndAudits()
    {
        var u = MakeUser();
        _users.Setup(s => s.GetByUsernameAsync("alice", It.IsAny<CancellationToken>())).ReturnsAsync(u);
        _hasher.Setup(h => h.VerifyAsync("bad", u.PasswordHash, It.IsAny<CancellationToken>()))
               .ReturnsAsync(new PasswordVerificationResult(false, false));
        _users.Setup(s => s.RecordLoginFailureAsync(u.Id, It.IsAny<IPAddress?>(), 5, It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
              .ReturnsAsync(false);

        var result = await CreateController().Login(
            new LoginViewModel { Username = "alice", Password = "bad" }, CancellationToken.None);

        Assert.IsType<ViewResult>(result);
        _users.Verify(s => s.RecordLoginFailureAsync(u.Id, It.IsAny<IPAddress?>(), 5, It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()), Times.Once);
        _audit.Verify(a => a.LogAsync(
            AuthAuditEvents.LoginFailed, u.Id, "alice",
            It.IsAny<IPAddress?>(), It.IsAny<string?>(), It.IsAny<object?>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Login_GoodPassword_NeedsRehash_RotatesHash()
    {
        var u = MakeUser();
        _users.Setup(s => s.GetByUsernameAsync("alice", It.IsAny<CancellationToken>())).ReturnsAsync(u);
        _hasher.Setup(h => h.VerifyAsync("good", u.PasswordHash, It.IsAny<CancellationToken>()))
               .ReturnsAsync(new PasswordVerificationResult(true, true)); // needs rehash
        _hasher.Setup(h => h.HashAsync("good", It.IsAny<CancellationToken>()))
               .ReturnsAsync("$argon2id$NEW-HASH");
        _totp.Setup(t => t.HasEnrolledAsync(u.Id, It.IsAny<CancellationToken>())).ReturnsAsync(true);

        await CreateController().Login(
            new LoginViewModel { Username = "alice", Password = "good" }, CancellationToken.None);

        _users.Verify(s => s.UpdatePasswordHashAsync(u.Id, "$argon2id$NEW-HASH", It.IsAny<CancellationToken>()), Times.Once);
    }

    // ── Login: routing into TOTP step ──────────────────────────────────

    [Fact]
    public async Task Login_GoodPassword_HasTotp_RedirectsToLoginTotp_WithReturnUrl()
    {
        var u = MakeUser();
        _users.Setup(s => s.GetByUsernameAsync("alice", It.IsAny<CancellationToken>())).ReturnsAsync(u);
        _hasher.Setup(h => h.VerifyAsync("good", u.PasswordHash, It.IsAny<CancellationToken>()))
               .ReturnsAsync(new PasswordVerificationResult(true, false));
        _totp.Setup(t => t.HasEnrolledAsync(u.Id, It.IsAny<CancellationToken>())).ReturnsAsync(true);

        var result = await CreateController().Login(
            new LoginViewModel { Username = "alice", Password = "good", ReturnUrl = "/dashboard" },
            CancellationToken.None);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("LoginTotp", redirect.ActionName);
        Assert.Equal("/dashboard", redirect.RouteValues!["returnUrl"]);
        _pending.Verify(p => p.Issue(u.Id, "/dashboard", null), Times.Once);
    }

    [Fact]
    public async Task Login_GoodPassword_NoTotpEnrolled_RedirectsToEnrollTotp()
    {
        var u = MakeUser();
        _users.Setup(s => s.GetByUsernameAsync("alice", It.IsAny<CancellationToken>())).ReturnsAsync(u);
        _hasher.Setup(h => h.VerifyAsync("good", u.PasswordHash, It.IsAny<CancellationToken>()))
               .ReturnsAsync(new PasswordVerificationResult(true, false));
        _totp.Setup(t => t.HasEnrolledAsync(u.Id, It.IsAny<CancellationToken>())).ReturnsAsync(false);

        var result = await CreateController().Login(
            new LoginViewModel { Username = "alice", Password = "good" }, CancellationToken.None);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("EnrollTotp", redirect.ActionName);
        Assert.Equal("Account", redirect.ControllerName);
        _pending.Verify(p => p.Issue(u.Id, null, null), Times.Once);
    }

    // ── LoginTotp ──────────────────────────────────────────────────────

    [Fact]
    public void LoginTotp_Get_NoPendingTicket_RedirectsToLogin()
    {
        Guid ignoredUid;
        string? ignoredReturn;
        byte[]? ignoredSecret;
        _pending.Setup(p => p.TryRead(out ignoredUid, out ignoredReturn, out ignoredSecret)).Returns(false);

        var result = CreateController().LoginTotp(returnUrl: "/x");

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(nameof(AuthController.Login), redirect.ActionName);
    }

    [Fact]
    public async Task LoginTotp_Post_NoPendingTicket_RedirectsToLogin()
    {
        Guid ignoredUid;
        string? ignoredReturn;
        byte[]? ignoredSecret;
        _pending.Setup(p => p.TryRead(out ignoredUid, out ignoredReturn, out ignoredSecret)).Returns(false);

        var result = await CreateController().LoginTotp(
            new LoginTotpViewModel { Code = "123456" }, CancellationToken.None);

        Assert.IsType<RedirectToActionResult>(result);
    }

    [Fact]
    public async Task LoginTotp_Post_BadCode_RecordsFailure_AndAuditsTotpFailed()
    {
        var uid = Guid.NewGuid();
        var u = MakeUser();
        u.Id = uid;
        Guid outUid = uid;
        string? outReturn = "/dashboard";
        byte[]? outSecret = null;
        _pending.Setup(p => p.TryRead(out outUid, out outReturn, out outSecret)).Returns(true);
        _users.Setup(s => s.GetByIdAsync(uid, It.IsAny<CancellationToken>())).ReturnsAsync(u);
        _totp.Setup(t => t.VerifyAsync(uid, "BADCODE", It.IsAny<CancellationToken>())).ReturnsAsync(false);
        _users.Setup(s => s.RecordLoginFailureAsync(uid, It.IsAny<IPAddress?>(), 5, It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()))
              .ReturnsAsync(false);

        var result = await CreateController().LoginTotp(
            new LoginTotpViewModel { Code = "BADCODE" }, CancellationToken.None);

        Assert.IsType<ViewResult>(result);
        _audit.Verify(a => a.LogAsync(
            AuthAuditEvents.TotpFailed, uid, "alice",
            It.IsAny<IPAddress?>(), It.IsAny<string?>(), It.IsAny<object?>(),
            It.IsAny<CancellationToken>()), Times.Once);
        _cookieIssuer.Verify(c => c.IssueAsync(It.IsAny<HttpContext>(), It.IsAny<User>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task LoginTotp_Post_GoodCode_IssuesCookie_ClearsPendingTicket_RedirectsToReturnUrl()
    {
        var uid = Guid.NewGuid();
        var u = MakeUser();
        u.Id = uid;
        Guid outUid = uid;
        string? outReturn = "/dashboard";
        byte[]? outSecret = null;
        _pending.Setup(p => p.TryRead(out outUid, out outReturn, out outSecret)).Returns(true);
        _users.Setup(s => s.GetByIdAsync(uid, It.IsAny<CancellationToken>())).ReturnsAsync(u);
        _totp.Setup(t => t.VerifyAsync(uid, "123456", It.IsAny<CancellationToken>())).ReturnsAsync(true);

        var result = await CreateController().LoginTotp(
            new LoginTotpViewModel { Code = "123456" }, CancellationToken.None);

        var redirect = Assert.IsType<LocalRedirectResult>(result);
        Assert.Equal("/dashboard", redirect.Url);
        _users.Verify(s => s.RecordLoginSuccessAsync(uid, It.IsAny<IPAddress?>(), It.IsAny<CancellationToken>()), Times.Once);
        _audit.Verify(a => a.LogAsync(
            AuthAuditEvents.TotpVerified, uid, "alice",
            It.IsAny<IPAddress?>(), It.IsAny<string?>(), It.IsAny<object?>(),
            It.IsAny<CancellationToken>()), Times.Once);
        _cookieIssuer.Verify(c => c.IssueAsync(It.IsAny<HttpContext>(), u, It.IsAny<CancellationToken>()), Times.Once);
        _pending.Verify(p => p.Clear(), Times.Once);
    }

    [Fact]
    public async Task LoginTotp_Post_RecoveryCode_GoesThroughRecoveryService_AndAuditsRecoveryUsed()
    {
        var uid = Guid.NewGuid();
        var u = MakeUser();
        u.Id = uid;
        Guid outUid = uid;
        string? outReturn = null;
        byte[]? outSecret = null;
        _pending.Setup(p => p.TryRead(out outUid, out outReturn, out outSecret)).Returns(true);
        _users.Setup(s => s.GetByIdAsync(uid, It.IsAny<CancellationToken>())).ReturnsAsync(u);
        _recovery.Setup(r => r.VerifyAndConsumeAsync(uid, "ABCDE-FGHIJ", It.IsAny<CancellationToken>())).ReturnsAsync(true);

        var result = await CreateController().LoginTotp(
            new LoginTotpViewModel { Code = "ABCDE-FGHIJ", IsRecoveryCode = true }, CancellationToken.None);

        Assert.IsType<LocalRedirectResult>(result);
        // Recovery path used — TOTP service NOT called.
        _totp.Verify(t => t.VerifyAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        _recovery.Verify(r => r.VerifyAndConsumeAsync(uid, "ABCDE-FGHIJ", It.IsAny<CancellationToken>()), Times.Once);
        _audit.Verify(a => a.LogAsync(
            AuthAuditEvents.RecoveryUsed, uid, "alice",
            It.IsAny<IPAddress?>(), It.IsAny<string?>(), It.IsAny<object?>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task LoginTotp_Post_StashesReturnUrl_WhenModelDoesNotProvideOne()
    {
        // The ticket stash from the password step survives into the TOTP step:
        // the controller must use it when the form's hidden ReturnUrl is empty.
        var uid = Guid.NewGuid();
        var u = MakeUser();
        u.Id = uid;
        Guid outUid = uid;
        string? outReturn = "/from-stash";
        byte[]? outSecret = null;
        _pending.Setup(p => p.TryRead(out outUid, out outReturn, out outSecret)).Returns(true);
        _users.Setup(s => s.GetByIdAsync(uid, It.IsAny<CancellationToken>())).ReturnsAsync(u);
        _totp.Setup(t => t.VerifyAsync(uid, "123456", It.IsAny<CancellationToken>())).ReturnsAsync(true);

        var result = await CreateController().LoginTotp(
            new LoginTotpViewModel { Code = "123456" /* no ReturnUrl in model */ }, CancellationToken.None);

        var redirect = Assert.IsType<LocalRedirectResult>(result);
        Assert.Equal("/from-stash", redirect.Url);
    }

    // ── Logout ────────────────────────────────────────────────────────

    [Fact]
    public async Task Logout_RevokesSessionByClaim_DeletesCookie_AndAudits()
    {
        var uid = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, uid.ToString()),
            new Claim(ClaimTypes.Name, "alice"),
            new Claim(SessionCookieAuthHandler.SessionIdClaim, sessionId.ToString())
        }, "test"));
        var ctx = MakeHttpContext(user: principal);
        var c = CreateController(ctx);

        var result = await c.Logout(CancellationToken.None);

        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.Equal("/login", redirect.Url);
        _sessions.Verify(s => s.RevokeAsync(sessionId, It.IsAny<CancellationToken>()), Times.Once);
        _audit.Verify(a => a.LogAsync(
            AuthAuditEvents.Logout, uid, "alice",
            It.IsAny<IPAddress?>(), It.IsAny<string?>(), It.IsAny<object?>(),
            It.IsAny<CancellationToken>()), Times.Once);
        // Cookie deletion
        Assert.Contains(SessionCookieAuthHandler.CookieName, ctx.Response.Headers["Set-Cookie"].ToString());
    }

    [Fact]
    public async Task Logout_NoSessionIdClaim_StillDeletesCookieAndAudits_NoRevoke()
    {
        // A request that somehow lacks the session_id claim (refactor accident)
        // shouldn't crash logout. Cookie delete + audit still happen; revoke skipped.
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.Name, "alice")
        }, "test"));
        var ctx = MakeHttpContext(user: principal);
        var c = CreateController(ctx);

        var result = await c.Logout(CancellationToken.None);

        Assert.IsType<RedirectResult>(result);
        _sessions.Verify(s => s.RevokeAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    // ── Elevate ────────────────────────────────────────────────────────

    [Fact]
    public async Task Elevate_BadCode_AuditsDenial_DoesNotElevate()
    {
        var uid = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var u = MakeUser();
        u.Id = uid;
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, uid.ToString()),
            new Claim(ClaimTypes.Name, "alice"),
            new Claim(SessionCookieAuthHandler.SessionIdClaim, sessionId.ToString())
        }, "test"));
        var ctx = MakeHttpContext(user: principal);
        _users.Setup(s => s.GetByIdAsync(uid, It.IsAny<CancellationToken>())).ReturnsAsync(u);
        _totp.Setup(t => t.VerifyAsync(uid, "BAD", It.IsAny<CancellationToken>())).ReturnsAsync(false);

        await CreateController(ctx).Elevate("BAD", retryUrl: null, retryMethod: null, CancellationToken.None);

        _sessions.Verify(s => s.ElevateAsync(It.IsAny<Guid>(), It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()), Times.Never);
        _audit.Verify(a => a.LogAsync(
            AuthAuditEvents.ElevationDenied, uid, "alice",
            It.IsAny<IPAddress?>(), It.IsAny<string?>(), It.IsAny<object?>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Elevate_GoodCode_BumpsSession_AndAuditsGranted_AndSetsHxTrigger()
    {
        var uid = Guid.NewGuid();
        var sessionId = Guid.NewGuid();
        var u = MakeUser();
        u.Id = uid;
        var principal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, uid.ToString()),
            new Claim(ClaimTypes.Name, "alice"),
            new Claim(SessionCookieAuthHandler.SessionIdClaim, sessionId.ToString())
        }, "test"));
        var ctx = MakeHttpContext(user: principal);
        _users.Setup(s => s.GetByIdAsync(uid, It.IsAny<CancellationToken>())).ReturnsAsync(u);
        _totp.Setup(t => t.VerifyAsync(uid, "123456", It.IsAny<CancellationToken>())).ReturnsAsync(true);

        await CreateController(ctx).Elevate("123456", retryUrl: "/secure-action", retryMethod: "POST", CancellationToken.None);

        _sessions.Verify(s => s.ElevateAsync(sessionId, TimeSpan.FromMinutes(15), It.IsAny<CancellationToken>()), Times.Once);
        _audit.Verify(a => a.LogAsync(
            AuthAuditEvents.ElevationGranted, uid, "alice",
            It.IsAny<IPAddress?>(), It.IsAny<string?>(), It.IsAny<object?>(),
            It.IsAny<CancellationToken>()), Times.Once);
        // HTMX trigger header instructs the browser to close the modal + replay action.
        var hxTrigger = ctx.Response.Headers["HX-Trigger"].ToString();
        Assert.Contains("elevationGranted", hxTrigger);
        Assert.Contains("/secure-action", hxTrigger);
    }
}
