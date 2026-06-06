using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Mvc.ViewFeatures;
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
/// Regression coverage for the TOTP enrollment flow. Two real production bugs
/// caused by the original implementation:
///   1. GET /account/totp/enroll generated a fresh secret EVERY time, so any
///      page reload silently invalidated the QR the user just scanned with
///      DUO/Google Authenticator.
///   2. POST with a wrong code RedirectToAction'd back to GET, which tripped
///      bug #1 — one typo permanently bricked the enrollment session.
///
/// These tests pin the fix: the secret stays stable across re-renders, and a
/// bad-code POST re-renders the view (preserving secret + ModelState) instead
/// of redirecting.
/// </summary>
public class AccountControllerEnrollTotpTests
{
    private readonly Mock<IUserService> _users = new();
    private readonly FakeTotpService _rawTotp = new();
    private readonly Mock<IUserTotpService> _userTotp = new();
    private readonly Mock<IRecoveryCodeService> _recovery = new();
    private readonly Mock<ISessionService> _sessions = new();
    private readonly Mock<ISessionCookieIssuer> _cookieIssuer = new();
    private readonly Mock<IPasswordHasher> _hasher = new();
    private readonly Mock<IAuthAuditService> _audit = new();
    private readonly Mock<IPendingAuthTicket> _pending = new();
    private readonly Mock<NetFirewall.Services.Monitoring.IGeoIpLookupService> _geo = new();
    private readonly Mock<NetFirewall.Web.Auth.IAppInfoService> _appInfo = new();

    private readonly Guid _uid = Guid.NewGuid();
    private readonly User _user;
    private readonly byte[] _firstSecret = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };

    public AccountControllerEnrollTotpTests()
    {
        _user = new User
        {
            Id = _uid, Username = "alice", PasswordHash = "$argon2id$x",
            Role = UserRoles.Operator, IsActive = true
        };
        _users.Setup(u => u.GetByIdAsync(_uid, It.IsAny<CancellationToken>())).ReturnsAsync(_user);
    }

    /// <summary>
    /// Hand-rolled stub of <see cref="ITotpService"/>. Moq can't mock methods
    /// taking <c>ReadOnlySpan&lt;byte&gt;</c> (ref struct), so we use a real
    /// implementation with overridable behaviour per test.
    /// </summary>
    private sealed class FakeTotpService : ITotpService
    {
        public byte[] SecretToGenerate { get; set; } = new byte[20];
        public int GenerateCallCount { get; private set; }
        public long? VerifyResult { get; set; } = 1L;       // success by default
        public string? ExpectedCode { get; set; }            // if set, only matches this code

        public byte[] GenerateSecret() { GenerateCallCount++; return SecretToGenerate; }
        public string ToBase32(ReadOnlySpan<byte> secret) => "BASE32";
        public Uri BuildEnrollmentUri(ReadOnlySpan<byte> secret, string issuer, string account) =>
            new($"otpauth://totp/{issuer}:{account}?secret=BASE32");

        public long? Verify(ReadOnlySpan<byte> secret, string code, long? lastUsedStep, DateTimeOffset now)
        {
            if (ExpectedCode is not null && code != ExpectedCode) return null;
            return VerifyResult;
        }
    }

    private AccountController CreateController(Dictionary<string, object>? tempData = null)
    {
        var c = new AccountController(
            _users.Object, _rawTotp, _userTotp.Object, _recovery.Object,
            _sessions.Object, _cookieIssuer.Object, _hasher.Object, _audit.Object, _pending.Object,
            _geo.Object, _appInfo.Object);

        var ctx = new DefaultHttpContext();
        c.ControllerContext = new ControllerContext { HttpContext = ctx };

        // TempData backs the recovery-codes carry-over across the GET → POST → GET cycle.
        var tempDataProvider = new Mock<ITempDataProvider>();
        var tempDataDict = new TempDataDictionary(ctx, tempDataProvider.Object);
        if (tempData is not null)
            foreach (var kv in tempData) tempDataDict[kv.Key] = kv.Value;
        c.TempData = tempDataDict;
        return c;
    }

    private void StubPendingTicket(byte[]? existingSecret, string? returnUrl = null)
    {
        Guid outUid = _uid;
        string? outReturn = returnUrl;
        byte[]? outSecret = existingSecret;
        _pending.Setup(p => p.TryRead(out outUid, out outReturn, out outSecret)).Returns(true);
    }

    // ── REGRESSION #1: GET reuses pending secret instead of rotating ───

    [Fact]
    public async Task EnrollTotp_Get_ExistingSecretInTicket_IsReused_NotRotated()
    {
        // The user has already loaded the page once — secret is in the ticket.
        // A reload (second GET) must NOT generate a new secret, otherwise the
        // QR they scanned with DUO becomes invalid.
        StubPendingTicket(existingSecret: _firstSecret, returnUrl: "/x");

        var result = await CreateController().EnrollTotp(CancellationToken.None);

        Assert.IsType<ViewResult>(result);
        // Generator must NOT have been called — the existing secret was reused.
        Assert.Equal(0, _rawTotp.GenerateCallCount);
        // And the ticket isn't re-issued (would invalidate the existing one).
        _pending.Verify(p => p.Issue(It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<byte[]?>()), Times.Never);
    }

    [Fact]
    public async Task EnrollTotp_Get_NoSecretInTicket_GeneratesAndIssues()
    {
        // First visit: no secret in ticket → generate one and stash it.
        StubPendingTicket(existingSecret: null, returnUrl: "/x");
        _rawTotp.SecretToGenerate = _firstSecret;
        _recovery.Setup(r => r.RegenerateAsync(_uid, 10, It.IsAny<CancellationToken>()))
                 .ReturnsAsync(new[] { "AAAAA-AAAAA" });

        var result = await CreateController().EnrollTotp(CancellationToken.None);

        Assert.IsType<ViewResult>(result);
        Assert.Equal(1, _rawTotp.GenerateCallCount);
        _pending.Verify(p => p.Issue(_uid, "/x", _firstSecret), Times.Once);
    }

    [Fact]
    public async Task EnrollTotp_Get_NoPendingTicket_RedirectsToLogin()
    {
        Guid u; string? r; byte[]? s;
        _pending.Setup(p => p.TryRead(out u, out r, out s)).Returns(false);

        var result = await CreateController().EnrollTotp(CancellationToken.None);

        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.Equal("/login", redirect.Url);
    }

    [Fact]
    public async Task EnrollTotp_Get_RecoveryCodes_Cached_InTempData_AcrossReloads()
    {
        // The recovery codes the user wrote down on the first visit must
        // SURVIVE a page reload — a fresh batch would invalidate them.
        StubPendingTicket(existingSecret: _firstSecret);
        var stashed = new[] { "ABCDE-FGHIJ", "KLMNO-PQRST" };
        var c = CreateController(new Dictionary<string, object> { ["EnrollRecoveryCodes"] = stashed });

        var result = await c.EnrollTotp(CancellationToken.None);

        var view = Assert.IsType<ViewResult>(result);
        var vm = Assert.IsType<TotpEnrollViewModel>(view.Model);
        Assert.Equal(stashed, vm.RecoveryCodes);
        // RegenerateAsync MUST NOT have been called.
        _recovery.Verify(r => r.RegenerateAsync(It.IsAny<Guid>(), It.IsAny<int>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    // ── REGRESSION #2: POST with bad code re-renders view (no redirect) ─

    [Fact]
    public async Task EnrollTotp_Post_BadCode_ReRendersView_DoesNotRedirect_PreservesSecret()
    {
        // The fixed POST returns View(BuildVm()) on a bad code — NOT
        // RedirectToAction. This keeps both ModelState (the error message)
        // and the pending-ticket secret untouched.
        StubPendingTicket(existingSecret: _firstSecret);
        _rawTotp.VerifyResult = null; // Verify will return null = bad code

        var result = await CreateController().EnrollTotp(
            new TotpEnrollConfirmViewModel { Code = "BADCODE" }, CancellationToken.None);

        var view = Assert.IsType<ViewResult>(result); // ← view, not redirect
        Assert.IsType<TotpEnrollViewModel>(view.Model);
        // No new secret generated, no ticket re-issued, no enrollment recorded.
        Assert.Equal(0, _rawTotp.GenerateCallCount);
        _pending.Verify(p => p.Issue(It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<byte[]?>()), Times.Never);
        _userTotp.Verify(u => u.EnrollAsync(It.IsAny<Guid>(), It.IsAny<byte[]>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task EnrollTotp_Post_BadCode_AddsModelErrorOnCodeField()
    {
        StubPendingTicket(existingSecret: _firstSecret);
        _rawTotp.VerifyResult = null;

        var c = CreateController();
        await c.EnrollTotp(new TotpEnrollConfirmViewModel { Code = "BAD" }, CancellationToken.None);

        Assert.False(c.ModelState.IsValid);
        Assert.True(c.ModelState.ContainsKey("Code"));
        Assert.Contains(c.ModelState["Code"]!.Errors,
            e => e.ErrorMessage.Contains("does not match"));
    }

    [Fact]
    public async Task EnrollTotp_Post_NoPendingTicket_RedirectsToEnrollGet()
    {
        Guid u; string? r; byte[]? s;
        _pending.Setup(p => p.TryRead(out u, out r, out s)).Returns(false);

        var result = await CreateController().EnrollTotp(
            new TotpEnrollConfirmViewModel { Code = "x" }, CancellationToken.None);

        var redirect = Assert.IsType<RedirectResult>(result);
        Assert.Equal("/account/totp/enroll", redirect.Url);
    }

    // ── Happy path ─────────────────────────────────────────────────────

    [Fact]
    public async Task EnrollTotp_Post_GoodCode_PersistsSecret_IssuesCookie_ClearsPendingTicket()
    {
        StubPendingTicket(existingSecret: _firstSecret, returnUrl: "/dashboard");
        _rawTotp.VerifyResult = 42L;

        var c = CreateController();
        var result = await c.EnrollTotp(
            new TotpEnrollConfirmViewModel { Code = "123456" }, CancellationToken.None);

        var redirect = Assert.IsType<LocalRedirectResult>(result);
        Assert.Equal("/dashboard", redirect.Url);
        _userTotp.Verify(u => u.EnrollAsync(_uid, _firstSecret, It.IsAny<CancellationToken>()), Times.Once);
        _audit.Verify(a => a.LogAsync(
            AuthAuditEvents.TotpEnrolled, _uid, "alice",
            It.IsAny<System.Net.IPAddress?>(), It.IsAny<string?>(), It.IsAny<object?>(),
            It.IsAny<CancellationToken>()), Times.Once);
        _cookieIssuer.Verify(ci => ci.IssueAsync(It.IsAny<HttpContext>(), _user, It.IsAny<CancellationToken>()), Times.Once);
        _pending.Verify(p => p.Clear(), Times.Once);
    }
}
