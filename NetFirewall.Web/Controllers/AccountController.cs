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

/// <summary>
/// User-facing account flows: TOTP enrollment (forced after first login),
/// security page (change password, regenerate TOTP/recovery, list sessions).
/// </summary>
[Authorize] // most actions; AllowAnonymous on enrollment because the user is in mid-login flow
public sealed class AccountController : Controller
{
    private const string PendingUserKey = "auth.pending_user_id";

    private readonly IUserService _users;
    private readonly ITotpService _rawTotp;
    private readonly IUserTotpService _userTotp;
    private readonly IRecoveryCodeService _recovery;
    private readonly ISessionService _sessions;
    private readonly ISessionCookieIssuer _cookieIssuer;
    private readonly IPasswordHasher _hasher;
    private readonly IAuthAuditService _audit;

    public AccountController(
        IUserService users,
        ITotpService rawTotp,
        IUserTotpService userTotp,
        IRecoveryCodeService recovery,
        ISessionService sessions,
        ISessionCookieIssuer cookieIssuer,
        IPasswordHasher hasher,
        IAuthAuditService audit)
    {
        _users = users;
        _rawTotp = rawTotp;
        _userTotp = userTotp;
        _recovery = recovery;
        _sessions = sessions;
        _cookieIssuer = cookieIssuer;
        _hasher = hasher;
        _audit = audit;
    }

    // -------------------------------------------------- TOTP enrollment

    /// <summary>
    /// Forced TOTP enrollment after first login. The user is in the middle of
    /// the login flow (TempData[PendingUserKey] holds their id), not yet
    /// fully authenticated — so this action is anonymous.
    /// </summary>
    [HttpGet("/account/totp/enroll"), AllowAnonymous]
    public async Task<IActionResult> EnrollTotp(CancellationToken ct)
    {
        if (!TryGetPendingUserId(out var uid)) return Redirect("/login");
        var user = await _users.GetByIdAsync(uid, ct);
        if (user is null) return Redirect("/login");

        // Generate a fresh secret + recovery codes; persist them only when the
        // user proves they captured the secret (POST below verifies a code).
        var secret = _rawTotp.GenerateSecret();
        TempData["auth.enroll_secret"] = Convert.ToBase64String(secret);
        TempData[PendingUserKey] = uid.ToString();

        var codes = await _recovery.RegenerateAsync(uid, 10, ct);

        var vm = new TotpEnrollViewModel
        {
            SecretBase32 = _rawTotp.ToBase32(secret),
            OtpAuthUri = _rawTotp.BuildEnrollmentUri(secret, "NetFirewall", user.Username).ToString(),
            RecoveryCodes = codes
        };
        return View(vm);
    }

    [HttpPost("/account/totp/enroll"), AllowAnonymous, ValidateAntiForgeryToken]
    public async Task<IActionResult> EnrollTotp(TotpEnrollConfirmViewModel model, CancellationToken ct)
    {
        if (!TryGetPendingUserId(out var uid)) return Redirect("/login");
        var raw = TempData["auth.enroll_secret"] as string;
        if (string.IsNullOrEmpty(raw)) return Redirect("/account/totp/enroll");
        TempData[PendingUserKey] = uid.ToString();

        var user = await _users.GetByIdAsync(uid, ct);
        if (user is null) return Redirect("/login");

        if (!ModelState.IsValid)
        {
            // Restore TempData so the GET re-renders the same QR.
            TempData["auth.enroll_secret"] = raw;
            return RedirectToAction(nameof(EnrollTotp));
        }

        var secret = Convert.FromBase64String(raw);
        var step = _rawTotp.Verify(secret, model.Code, lastUsedStep: null, DateTimeOffset.UtcNow);
        if (step is null)
        {
            ModelState.AddModelError(nameof(model.Code), "That code does not match. Try again.");
            TempData["auth.enroll_secret"] = raw;
            return RedirectToAction(nameof(EnrollTotp));
        }

        await _userTotp.EnrollAsync(uid, secret, ct);
        await _audit.LogAsync(AuthAuditEvents.TotpEnrolled, uid, user.Username,
            HttpContext.Connection.RemoteIpAddress, Request.Headers.UserAgent.ToString(), ct: ct);

        // Issue the real session cookie now and finish login.
        await _cookieIssuer.IssueAsync(HttpContext, user, ct);
        TempData.Remove(PendingUserKey);

        var returnUrl = TempData["auth.return_url"] as string;
        return LocalRedirect(string.IsNullOrEmpty(returnUrl) ? "/" : returnUrl);
    }

    // -------------------------------------------------- /account/security

    [HttpGet("/account/security")]
    public async Task<IActionResult> Security(CancellationToken ct)
    {
        var uid = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var user = await _users.GetByIdAsync(uid, ct);
        var totpEnrolled = await _userTotp.HasEnrolledAsync(uid, ct);
        var unusedRecovery = await _recovery.CountUnusedAsync(uid, ct);
        var sessions = await _sessions.ListActiveAsync(uid, ct);

        ViewBag.User = user;
        ViewBag.TotpEnrolled = totpEnrolled;
        ViewBag.UnusedRecovery = unusedRecovery;
        ViewBag.Sessions = sessions;
        return View();
    }

    [HttpPost("/account/security/revoke/{sessionId:guid}"), ValidateAntiForgeryToken]
    public async Task<IActionResult> RevokeSession(Guid sessionId, CancellationToken ct)
    {
        await _sessions.RevokeAsync(sessionId, ct);
        await _audit.LogAsync(AuthAuditEvents.SessionRevoked,
            Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!), User.Identity?.Name,
            HttpContext.Connection.RemoteIpAddress, Request.Headers.UserAgent.ToString(),
            new { sessionId }, ct);
        return this.ToHtmxResponse(ServiceResponse<object>.Ok(new { }, "Session revoked."));
    }

    [HttpPost("/account/security/recovery/regenerate"), ValidateAntiForgeryToken]
    public async Task<IActionResult> RegenerateRecovery(CancellationToken ct)
    {
        var uid = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var codes = await _recovery.RegenerateAsync(uid, 10, ct);
        await _audit.LogAsync(AuthAuditEvents.RecoveryRegen, uid, User.Identity?.Name,
            HttpContext.Connection.RemoteIpAddress, Request.Headers.UserAgent.ToString(), ct: ct);
        return Json(new { success = true, codes });
    }

    private bool TryGetPendingUserId(out Guid id)
    {
        id = Guid.Empty;
        var raw = TempData.Peek(PendingUserKey) as string;
        return !string.IsNullOrEmpty(raw) && Guid.TryParse(raw, out id);
    }
}
