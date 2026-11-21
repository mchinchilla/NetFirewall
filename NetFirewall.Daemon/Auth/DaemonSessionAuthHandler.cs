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
    public const string SessionIdClaim = "session_id";

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
        // user-facing session owner. TimeSpan.Zero is the "validate but don't
        // slide" signal recognised by SessionService.ValidateAsync; without it
        // the daemon would overwrite expires_at to "now" and log the Web
        // operator out on their next request.
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
            new Claim(AuthLevelClaim, elevated ? AuthLevels.Elevated : AuthLevels.Basic),
            // Required by AuthEndpoints.LogoutAsync to revoke the right session
            // (we get a token in the header, the session ID identifies the row).
            new Claim(SessionIdClaim, session.Id.ToString())
        };
        var identity = new ClaimsIdentity(claims, SchemeName, ClaimTypes.Name, ClaimTypes.Role);
        var principal = new ClaimsPrincipal(identity);
        return AuthenticateResult.Success(new AuthenticationTicket(principal, SchemeName));
    }
}

/// <summary>
/// Endpoint metadata: the request must carry an <b>elevated</b> session (recent TOTP
/// step-up) of a user with the Admin or Operator role. The root-peer principal
/// (<see cref="RootPeerBypassMiddleware"/>) qualifies. Daemon-side mirror of the Web's
/// <c>RequireElevatedAttribute</c>; answers 403 (the request is authenticated, it just
/// lacks the elevation) and never prompts.
///
/// <para>Enforced by <see cref="DaemonEndpointGateMiddleware"/> — a plain marker, because
/// minimal APIs never run MVC filters.</para>
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public sealed class DaemonRequireElevatedAttribute : Attribute;
