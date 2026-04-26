using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Auth;
using NetFirewall.Web.Auth;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Auth;

namespace NetFirewall.Web.Controllers;

[AllowAnonymous]
public sealed class AuthController : Controller
{
    private const int FailedThreshold = 5;
    private static readonly TimeSpan LockDuration = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan ElevationDuration = TimeSpan.FromMinutes(15);

    private readonly IUserService _users;
    private readonly IUserTotpService _totp;
    private readonly IRecoveryCodeService _recovery;
    private readonly ISessionService _sessions;
    private readonly ISessionCookieIssuer _cookieIssuer;
    private readonly IPasswordHasher _hasher;
    private readonly IAuthAuditService _audit;
    private readonly IPendingAuthTicket _pending;
    private readonly ILogger<AuthController> _logger;

    public AuthController(
        IUserService users,
        IUserTotpService totp,
        IRecoveryCodeService recovery,
        ISessionService sessions,
        ISessionCookieIssuer cookieIssuer,
        IPasswordHasher hasher,
        IAuthAuditService audit,
        IPendingAuthTicket pending,
        ILogger<AuthController> logger)
    {
        _users = users;
        _totp = totp;
        _recovery = recovery;
        _sessions = sessions;
        _cookieIssuer = cookieIssuer;
        _hasher = hasher;
        _audit = audit;
        _pending = pending;
        _logger = logger;
    }

    // ---------------------------------------------------------------- /login

    [HttpGet("/login")]
    public IActionResult Login(string? returnUrl = null) => View(new LoginViewModel { ReturnUrl = returnUrl });

    [HttpPost("/login"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Login(LoginViewModel model, CancellationToken ct)
    {
        if (!ModelState.IsValid) return View(model);

        var ip = ClientIp();
        var ua = Request.Headers.UserAgent.ToString();
        var user = await _users.GetByUsernameAsync(model.Username, ct);

        // Constant-ish-time response: always do a real-cost hash so timing
        // doesn't reveal user existence. Salt + hash both 32 bytes (matching
        // Argon2PasswordHasher defaults) so the work matches a true verify.
        if (user is null)
        {
            const string dummyHash = "$argon2id$v=19$m=65536,t=3,p=4$" +
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$" +
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            await _hasher.VerifyAsync(model.Password, dummyHash, ct);
            await _audit.LogAsync(AuthAuditEvents.LoginFailed, username: model.Username, ip: ip, userAgent: ua,
                detail: new { reason = "user_not_found" }, ct: ct);
            ModelState.AddModelError(string.Empty, "Username or password is invalid.");
            return View(model);
        }

        if (!user.IsActive)
        {
            await _audit.LogAsync(AuthAuditEvents.LoginFailed, user.Id, user.Username, ip, ua,
                new { reason = "inactive" }, ct);
            ModelState.AddModelError(string.Empty, "This account is disabled.");
            return View(model);
        }

        if (user.LockedUntil is { } until && until > DateTimeOffset.UtcNow)
        {
            await _audit.LogAsync(AuthAuditEvents.LoginLocked, user.Id, user.Username, ip, ua,
                new { until }, ct);
            ModelState.AddModelError(string.Empty, $"Account locked until {until.LocalDateTime:t}.");
            return View(model);
        }

        var verify = await _hasher.VerifyAsync(model.Password, user.PasswordHash, ct);
        if (!verify.Matches)
        {
            var nowLocked = await _users.RecordLoginFailureAsync(user.Id, ip, FailedThreshold, LockDuration, ct);
            await _audit.LogAsync(AuthAuditEvents.LoginFailed, user.Id, user.Username, ip, ua,
                new { reason = "bad_password", locked = nowLocked }, ct);
            ModelState.AddModelError(string.Empty, "Username or password is invalid.");
            return View(model);
        }

        if (verify.NeedsRehash)
            await _users.UpdatePasswordHashAsync(user.Id, await _hasher.HashAsync(model.Password, ct), ct);

        // Step 2: TOTP. If the user hasn't enrolled yet, force enrollment now.
        var hasTotp = await _totp.HasEnrolledAsync(user.Id, ct);
        _pending.Issue(user.Id, model.ReturnUrl);

        if (!hasTotp)
            return RedirectToAction("EnrollTotp", "Account");

        return RedirectToAction(nameof(LoginTotp), new { returnUrl = model.ReturnUrl });
    }

    // ---------------------------------------------------------- /login/totp

    [HttpGet("/login/totp")]
    public IActionResult LoginTotp(string? returnUrl = null)
    {
        if (!_pending.TryRead(out _, out var stashedReturn, out _))
            return RedirectToAction(nameof(Login), new { returnUrl });
        return View(new LoginTotpViewModel { ReturnUrl = returnUrl ?? stashedReturn });
    }

    [HttpPost("/login/totp"), ValidateAntiForgeryToken]
    public async Task<IActionResult> LoginTotp(LoginTotpViewModel model, CancellationToken ct)
    {
        if (!_pending.TryRead(out var userId, out var stashedReturn, out _))
            return RedirectToAction(nameof(Login), new { returnUrl = model.ReturnUrl });

        if (string.IsNullOrEmpty(model.ReturnUrl)) model.ReturnUrl = stashedReturn;

        if (!ModelState.IsValid) return View(model);

        var user = await _users.GetByIdAsync(userId, ct);
        if (user is null) return RedirectToAction(nameof(Login));

        var ip = ClientIp();
        var ua = Request.Headers.UserAgent.ToString();
        var ok = model.IsRecoveryCode
            ? await _recovery.VerifyAndConsumeAsync(user.Id, model.Code, ct)
            : await _totp.VerifyAsync(user.Id, model.Code, ct);

        if (!ok)
        {
            var locked = await _users.RecordLoginFailureAsync(user.Id, ip, FailedThreshold, LockDuration, ct);
            await _audit.LogAsync(
                model.IsRecoveryCode ? AuthAuditEvents.RecoveryUsed : AuthAuditEvents.TotpFailed,
                user.Id, user.Username, ip, ua,
                new { matched = false, locked }, ct);
            ModelState.AddModelError(nameof(model.Code), "Invalid code.");
            return View(model);
        }

        await _users.RecordLoginSuccessAsync(user.Id, ip, ct);
        await _audit.LogAsync(
            model.IsRecoveryCode ? AuthAuditEvents.RecoveryUsed : AuthAuditEvents.TotpVerified,
            user.Id, user.Username, ip, ua, ct: ct);

        await _cookieIssuer.IssueAsync(HttpContext, user, ct);
        _pending.Clear();

        return LocalRedirect(string.IsNullOrEmpty(model.ReturnUrl) ? "/" : model.ReturnUrl);
    }

    // ----------------------------------------------------------- /auth/elevate

    [HttpPost("/auth/elevate"), ValidateAntiForgeryToken, Authorize]
    public async Task<IActionResult> Elevate([FromForm] string code, [FromForm] string? retryUrl, [FromForm] string? retryMethod, CancellationToken ct)
    {
        var userId = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var sessionId = Guid.Parse(User.FindFirstValue(SessionCookieAuthHandler.SessionIdClaim)!);
        var user = await _users.GetByIdAsync(userId, ct);
        if (user is null) return Unauthorized();

        var ok = await _totp.VerifyAsync(userId, code ?? string.Empty, ct);
        var ip = ClientIp();
        var ua = Request.Headers.UserAgent.ToString();

        if (!ok)
        {
            await _audit.LogAsync(AuthAuditEvents.ElevationDenied, userId, user.Username, ip, ua, ct: ct);
            return this.ToHtmxResponse(ServiceResponse<object>.Fail("Invalid TOTP code."));
        }

        await _sessions.ElevateAsync(sessionId, ElevationDuration, ct);
        await _audit.LogAsync(AuthAuditEvents.ElevationGranted, userId, user.Username, ip, ua,
            new { duration = ElevationDuration.TotalMinutes, retry = new { url = retryUrl, method = retryMethod } }, ct);

        // Tell the modal to close + replay the original action.
        Response.Headers["HX-Trigger"] = System.Text.Json.JsonSerializer.Serialize(new
        {
            elevationGranted = new { url = retryUrl, method = retryMethod }
        });
        return this.ToHtmxResponse(ServiceResponse<object>.Ok(new { }, "Elevation granted."));
    }

    // ----------------------------------------------------------- /logout

    [HttpPost("/logout"), ValidateAntiForgeryToken, Authorize]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        if (Guid.TryParse(User.FindFirstValue(SessionCookieAuthHandler.SessionIdClaim), out var sessionId))
        {
            await _sessions.RevokeAsync(sessionId, ct);
        }
        Response.Cookies.Delete(SessionCookieAuthHandler.CookieName, new CookieOptions { Path = "/" });

        await _audit.LogAsync(AuthAuditEvents.Logout,
            Guid.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var uid) ? uid : null,
            User.Identity?.Name, ClientIp(), Request.Headers.UserAgent.ToString(), ct: ct);

        return Redirect("/login");
    }

    // ---------------------------------------------------------- helpers

    internal IPAddress? ClientIp()
    {
        // Honor X-Forwarded-For only if a forwarded headers middleware is configured;
        // for now, prefer the connection peer.
        return HttpContext.Connection.RemoteIpAddress;
    }
}
