using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Auth;

namespace NetFirewall.Daemon.Auth;

public sealed class DaemonSessionOptions : AuthenticationSchemeOptions
{
    public string HeaderName { get; set; } = "X-NetFw-Session";
}

/// <summary>
/// Validates the <c>X-NetFw-Session</c> header against <c>user_sessions</c>.
/// On success, builds a ClaimsPrincipal carrying user id, role, and current
/// auth_level — endpoints use <c>[Authorize(Roles = ...)]</c> and a custom
/// <c>RequireElevatedAttribute</c> (server-side mirror of the Web's) to gate
/// destructive actions.
/// </summary>
public sealed class DaemonSessionAuthHandler : AuthenticationHandler<DaemonSessionOptions>
{
    public const string SchemeName = "DaemonSession";
    public const string AuthLevelClaim = "auth_level";

    private readonly ISessionService _sessions;
    private readonly IUserService _users;

    public DaemonSessionAuthHandler(
        IOptionsMonitor<DaemonSessionOptions> options,
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
        var token = Request.Headers[Options.HeaderName].ToString();
        if (string.IsNullOrEmpty(token)) return AuthenticateResult.NoResult();

        // Sliding window for daemon validations is irrelevant — the Web is the
        // user-facing session owner. Pass a 0 lifetime so we don't push expiry
        // forward from a daemon hit.
        var session = await _sessions.ValidateAsync(token, TimeSpan.Zero, Context.RequestAborted);
        if (session is null) return AuthenticateResult.Fail("session invalid or expired");

        var user = await _users.GetByIdAsync(session.UserId, Context.RequestAborted);
        if (user is null || !user.IsActive) return AuthenticateResult.Fail("user inactive");

        var elevated = session.IsElevated(DateTimeOffset.UtcNow);
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.Role, user.Role),
            new Claim(AuthLevelClaim, elevated ? AuthLevels.Elevated : AuthLevels.Basic)
        };
        var identity = new ClaimsIdentity(claims, SchemeName, ClaimTypes.Name, ClaimTypes.Role);
        var principal = new ClaimsPrincipal(identity);
        return AuthenticateResult.Success(new AuthenticationTicket(principal, SchemeName));
    }
}

/// <summary>
/// Daemon-side mirror of the Web's <c>RequireElevatedAttribute</c>. Returns
/// 403 Forbidden (not 401) because the request IS authenticated — it just
/// lacks the elevated claim. The Web's elevation modal flow only runs in
/// the browser; the daemon never prompts.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public sealed class DaemonRequireElevatedAttribute : Attribute, Microsoft.AspNetCore.Mvc.Filters.IAsyncAuthorizationFilter
{
    public Task OnAuthorizationAsync(Microsoft.AspNetCore.Mvc.Filters.AuthorizationFilterContext context)
    {
        var user = context.HttpContext.User;
        if (user.Identity?.IsAuthenticated != true)
        {
            context.Result = new Microsoft.AspNetCore.Mvc.UnauthorizedResult();
            return Task.CompletedTask;
        }
        var level = user.FindFirstValue(DaemonSessionAuthHandler.AuthLevelClaim);
        if (!string.Equals(level, AuthLevels.Elevated, StringComparison.OrdinalIgnoreCase))
        {
            context.Result = new Microsoft.AspNetCore.Mvc.ObjectResult(new
            {
                error = "elevation_required",
                message = "This operation requires an elevated session — re-prompt TOTP in the Web."
            }) { StatusCode = StatusCodes.Status403Forbidden };
            return Task.CompletedTask;
        }
        return Task.CompletedTask;
    }
}
