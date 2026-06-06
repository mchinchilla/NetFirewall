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
    private readonly IUserService _users;
    private readonly ITotpService _rawTotp;
    private readonly IUserTotpService _userTotp;
    private readonly IRecoveryCodeService _recovery;
    private readonly ISessionService _sessions;
    private readonly ISessionCookieIssuer _cookieIssuer;
    private readonly IPasswordHasher _hasher;
    private readonly IAuthAuditService _audit;
    private readonly IPendingAuthTicket _pending;
    private readonly NetFirewall.Services.Monitoring.IGeoIpLookupService _geo;
    private readonly IAppInfoService _appInfo;

    public AccountController(
        IUserService users,
        ITotpService rawTotp,
        IUserTotpService userTotp,
        IRecoveryCodeService recovery,
        ISessionService sessions,
        ISessionCookieIssuer cookieIssuer,
        IPasswordHasher hasher,
        IAuthAuditService audit,
        IPendingAuthTicket pending,
        NetFirewall.Services.Monitoring.IGeoIpLookupService geo,
        IAppInfoService appInfo)
    {
        _users = users;
        _rawTotp = rawTotp;
        _userTotp = userTotp;
        _recovery = recovery;
        _sessions = sessions;
        _cookieIssuer = cookieIssuer;
        _hasher = hasher;
        _audit = audit;
        _pending = pending;
        _geo = geo;
        _appInfo = appInfo;
    }

    // -------------------------------------------------- connection info

    // Lazy-loaded fragment for the "Connecting from" card in the account dropdown.
    // Loaded on demand (HTMX hx-get when the dropdown opens) so the geo lookup
    // doesn't run on every authenticated page render. For a LAN client the geo
    // describes the firewall's WAN egress (see IGeoIpLookupService.LookupForClientAsync).
    [HttpGet("/account/connection")]
    public async Task<IActionResult> Connection(CancellationToken ct)
    {
        var clientIp = HttpContext.Connection.RemoteIpAddress;
        var displayIp = clientIp?.ToString() ?? "—";
        if (displayIp == "::1") displayIp = "127.0.0.1";

        var geo = await _geo.LookupForClientAsync(clientIp, ct);
        var vm = new ConnectionInfoViewModel(displayIp, geo, _appInfo.StartedAt, _appInfo.Uptime);
        return PartialView("_ConnectingFromCard", vm);
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
        if (!_pending.TryRead(out var uid, out var stashedReturn, out var existingSecret)) return Redirect("/login");
        var user = await _users.GetByIdAsync(uid, ct);
        if (user is null) return Redirect("/login");

        // Reuse the pending secret if one already exists for this enrollment
        // attempt. Generating fresh on every GET would invalidate the QR the
        // user already scanned (so DUO/Google Authenticator codes would never
        // match) and silently rotate the secret on every page reload — both
        // visible as "TOTP just stopped working" with zero log evidence.
        var secret = existingSecret ?? _rawTotp.GenerateSecret();
        if (existingSecret is null)
            _pending.Issue(uid, stashedReturn, secret);

        // Recovery codes also stick to the first GET. Re-issuing them on every
        // refresh would invalidate the codes the user just wrote down.
        var codes = TempData["EnrollRecoveryCodes"] as IReadOnlyList<string>
                    ?? await _recovery.RegenerateAsync(uid, 10, ct);
        TempData["EnrollRecoveryCodes"] = codes;
        TempData.Keep("EnrollRecoveryCodes");

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
        if (!_pending.TryRead(out var uid, out var returnUrl, out var secret) || secret is null)
            return Redirect("/account/totp/enroll");

        var user = await _users.GetByIdAsync(uid, ct);
        if (user is null) return Redirect("/login");

        // Re-render the view (NOT a redirect) on validation/verify errors so
        // ModelState survives — and so we don't trip a fresh-secret rotation
        // by bouncing through the GET.
        var codes = TempData["EnrollRecoveryCodes"] as IReadOnlyList<string> ?? Array.Empty<string>();
        TempData.Keep("EnrollRecoveryCodes");

        TotpEnrollViewModel BuildVm() => new()
        {
            SecretBase32 = _rawTotp.ToBase32(secret),
            OtpAuthUri = _rawTotp.BuildEnrollmentUri(secret, "NetFirewall", user.Username).ToString(),
            RecoveryCodes = codes
        };

        if (!ModelState.IsValid)
            return View(BuildVm());

        var step = _rawTotp.Verify(secret, model.Code, lastUsedStep: null, DateTimeOffset.UtcNow);
        if (step is null)
        {
            ModelState.AddModelError(nameof(model.Code), "That code does not match. Try again.");
            return View(BuildVm());
        }

        await _userTotp.EnrollAsync(uid, secret, ct);
        await _audit.LogAsync(AuthAuditEvents.TotpEnrolled, uid, user.Username,
            HttpContext.Connection.RemoteIpAddress, Request.Headers.UserAgent.ToString(), ct: ct);

        // Issue the real session cookie now and finish login.
        await _cookieIssuer.IssueAsync(HttpContext, user, ct);
        _pending.Clear();
        TempData.Remove("EnrollRecoveryCodes");

        return LocalRedirect(ReturnUrlGuard.Sanitize(returnUrl));
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

    // -------------------------------------------------- /account/profile

    [HttpGet("/account/profile")]
    public async Task<IActionResult> Profile(CancellationToken ct)
    {
        var uid = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        var user = await _users.GetByIdAsync(uid, ct);
        if (user is null) return RedirectToAction("Login", "Auth");
        return View(NetFirewall.Web.Models.Auth.ProfileFormViewModel.FromUser(user));
    }

    [HttpPost("/account/profile"), ValidateAntiForgeryToken]
    public async Task<IActionResult> UpdateProfile(NetFirewall.Web.Models.Auth.ProfileFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid) return View("Profile", form);

        var uid = Guid.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!);
        try
        {
            var update = new UserProfileUpdate(
                FirstName:   form.FirstName,
                LastName:    form.LastName,
                DisplayName: form.DisplayName,
                Email:       form.Email,
                Phone:       form.Phone,
                Timezone:    form.Timezone,
                Locale:      form.Locale);
            var saved = await _users.UpdateProfileAsync(uid, update, ct);
            await _audit.LogAsync(AuthAuditEvents.ProfileUpdated, saved.Id, saved.Username,
                HttpContext.Connection.RemoteIpAddress, Request.Headers.UserAgent.ToString(), ct: ct);
            return View("Profile", NetFirewall.Web.Models.Auth.ProfileFormViewModel.FromUser(saved));
        }
        catch (Exception ex)
        {
            ModelState.AddModelError(string.Empty, $"Save failed: {ex.Message}");
            return View("Profile", form);
        }
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

}
