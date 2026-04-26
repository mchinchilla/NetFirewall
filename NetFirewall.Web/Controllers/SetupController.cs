using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Auth;
using NetFirewall.Web.Auth;
using NetFirewall.Web.Auth.Bootstrap;
using NetFirewall.Web.Models.Auth;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// First-run admin creation gated by the one-time bootstrap token. Endpoint
/// returns 404 once a user already exists OR the token has been consumed.
/// </summary>
[AllowAnonymous]
public sealed class SetupController : Controller
{
    private readonly IBootstrapTokenStore _tokenStore;
    private readonly IUserService _users;
    private readonly IPasswordHasher _hasher;
    private readonly IAuthAuditService _audit;
    private readonly IPendingAuthTicket _pending;

    public SetupController(
        IBootstrapTokenStore tokenStore,
        IUserService users,
        IPasswordHasher hasher,
        IAuthAuditService audit,
        IPendingAuthTicket pending)
    {
        _tokenStore = tokenStore;
        _users = users;
        _hasher = hasher;
        _audit = audit;
        _pending = pending;
    }

    [HttpGet("/setup/bootstrap")]
    public async Task<IActionResult> Bootstrap(string? token, CancellationToken ct)
    {
        if (!_tokenStore.IsActive) return NotFound();
        if (await _users.CountAsync(ct) > 0) return NotFound();
        if (string.IsNullOrEmpty(token) || !_tokenStore.Verify(token))
            return View("BootstrapInvalid");

        return View(new BootstrapViewModel { Token = token });
    }

    [HttpPost("/setup/bootstrap"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Bootstrap(BootstrapViewModel model, CancellationToken ct)
    {
        if (!_tokenStore.IsActive) return NotFound();
        if (await _users.CountAsync(ct) > 0) return NotFound();
        if (!_tokenStore.Verify(model.Token)) return View("BootstrapInvalid");

        if (!ModelState.IsValid) return View(model);

        // Username uniqueness — race-safe via the unique index, but check first for nicer UX.
        if (await _users.GetByUsernameAsync(model.Username, ct) is not null)
        {
            ModelState.AddModelError(nameof(model.Username), "That username is already taken.");
            return View(model);
        }

        var hash = await _hasher.HashAsync(model.Password, ct);
        var user = await _users.CreateAsync(new User
        {
            Username = model.Username,
            Email = model.Email,
            PasswordHash = hash,
            Role = UserRoles.Admin,
            IsActive = true
        }, ct);

        _tokenStore.Consume();

        await _audit.LogAsync(AuthAuditEvents.BootstrapUsed, user.Id, user.Username,
            HttpContext.Connection.RemoteIpAddress, Request.Headers.UserAgent.ToString(), ct: ct);
        await _audit.LogAsync(AuthAuditEvents.UserCreated, user.Id, user.Username,
            HttpContext.Connection.RemoteIpAddress, Request.Headers.UserAgent.ToString(),
            new { role = UserRoles.Admin, via = "bootstrap" }, ct);

        // The user just proved password ownership by setting it; carry them
        // straight into TOTP enrollment instead of bouncing through /login.
        _pending.Issue(user.Id);
        return RedirectToAction("EnrollTotp", "Account");
    }
}
