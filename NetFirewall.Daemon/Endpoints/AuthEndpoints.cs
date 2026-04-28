using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Daemon.Auth;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Auth;

namespace NetFirewall.Daemon.Endpoints;

/// <summary>
/// Auth endpoints for headless / TTY clients (the TUI). The Web NEVER hits
/// these — it has its own MVC <c>AuthController</c> with cookie issuance.
/// What's special about the TUI flow:
///
/// <list type="bullet">
///   <item>Single-step: TUI prompts for username + password + TOTP up front and
///   POSTs all three. No multi-page flow like the Web's <c>/login</c> →
///   <c>/login/totp</c> dance — a TTY can ask for everything at once.</item>
///   <item>Returns the session token in the body (not a cookie). The TUI
///   holds it in memory.</item>
///   <item>Same lockout / audit semantics as the Web. We share <c>IUserService</c>
///   and <c>IAuthAuditService</c>.</item>
/// </list>
/// </summary>
public static class AuthEndpoints
{
    private const int FailedThreshold = 5;
    private static readonly TimeSpan LockDuration = TimeSpan.FromMinutes(15);
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromHours(8);

    public static void MapAuthEndpoints(this IEndpointRouteBuilder app)
    {
        // /v1/auth/login is anonymous (you're trying to log in). Logout
        // requires the session header to be valid.
        app.MapPost("/v1/auth/login", LoginAsync).AllowAnonymous();

        app.MapPost("/v1/auth/logout", LogoutAsync)
            .RequireAuthorization();
    }

    private static async Task<IResult> LoginAsync(
        [FromBody] TuiLoginRequest body,
        HttpContext ctx,
        IUserService users,
        IPasswordHasher hasher,
        IUserTotpService totp,
        IRecoveryCodeService recovery,
        ISessionService sessions,
        IAuthAuditService audit,
        CancellationToken cancellationToken)
    {
        var ip = ctx.Connection.RemoteIpAddress;
        // The TUI doesn't send a User-Agent — synthesize one so the audit log
        // entry distinguishes TUI logins from Web logins at a glance.
        const string userAgent = "NetFirewall-TUI";

        if (string.IsNullOrWhiteSpace(body.Username))
            return ServiceFail("Username is required.");
        if (string.IsNullOrWhiteSpace(body.Password))
            return ServiceFail("Password is required.");
        if (string.IsNullOrWhiteSpace(body.TotpOrRecoveryCode))
            return ServiceFail("TOTP code or recovery code is required.");

        var user = await users.GetByUsernameAsync(body.Username, cancellationToken).ConfigureAwait(false);

        // Constant-ish-time response: do a real Argon2 hash even on user-not-found
        // so timing doesn't leak whether the username exists. Mirrors AuthController.
        if (user is null)
        {
            const string dummyHash = "$argon2id$v=19$m=65536,t=3,p=4$" +
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA$" +
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
            await hasher.VerifyAsync(body.Password, dummyHash, cancellationToken).ConfigureAwait(false);
            await audit.LogAsync(AuthAuditEvents.LoginFailed,
                username: body.Username, ip: ip, userAgent: userAgent,
                detail: new { reason = "user_not_found", channel = "tui" }, ct: cancellationToken).ConfigureAwait(false);
            return ServiceFail("Username or password is invalid.");
        }

        if (!user.IsActive)
        {
            await audit.LogAsync(AuthAuditEvents.LoginFailed, user.Id, user.Username, ip, userAgent,
                new { reason = "inactive", channel = "tui" }, cancellationToken).ConfigureAwait(false);
            return ServiceFail("This account is disabled.");
        }

        if (user.LockedUntil is { } until && until > DateTimeOffset.UtcNow)
        {
            await audit.LogAsync(AuthAuditEvents.LoginLocked, user.Id, user.Username, ip, userAgent,
                new { until, channel = "tui" }, cancellationToken).ConfigureAwait(false);
            return ServiceFail($"Account locked until {until.LocalDateTime:t}.");
        }

        var verify = await hasher.VerifyAsync(body.Password, user.PasswordHash, cancellationToken).ConfigureAwait(false);
        if (!verify.Matches)
        {
            var nowLocked = await users.RecordLoginFailureAsync(user.Id, ip, FailedThreshold, LockDuration, cancellationToken).ConfigureAwait(false);
            await audit.LogAsync(AuthAuditEvents.LoginFailed, user.Id, user.Username, ip, userAgent,
                new { reason = "bad_password", locked = nowLocked, channel = "tui" }, cancellationToken).ConfigureAwait(false);
            return ServiceFail("Username or password is invalid.");
        }

        if (verify.NeedsRehash)
        {
            await users.UpdatePasswordHashAsync(
                user.Id,
                await hasher.HashAsync(body.Password, cancellationToken).ConfigureAwait(false),
                cancellationToken).ConfigureAwait(false);
        }

        // TOTP / recovery-code verification. Same threshold semantics as Web —
        // a wrong code increments failure count and can lock the account.
        if (!await totp.HasEnrolledAsync(user.Id, cancellationToken).ConfigureAwait(false))
        {
            // We deliberately don't expose enrollment via the TUI today — the
            // user must enroll through the Web first. Could be relaxed later.
            return ServiceFail("This account has not enrolled TOTP yet. Enroll via the web UI before using the TUI.");
        }

        var totpOk = body.IsRecoveryCode
            ? await recovery.VerifyAndConsumeAsync(user.Id, body.TotpOrRecoveryCode, cancellationToken).ConfigureAwait(false)
            : await totp.VerifyAsync(user.Id, body.TotpOrRecoveryCode, cancellationToken).ConfigureAwait(false);

        if (!totpOk)
        {
            var nowLocked = await users.RecordLoginFailureAsync(user.Id, ip, FailedThreshold, LockDuration, cancellationToken).ConfigureAwait(false);
            await audit.LogAsync(
                body.IsRecoveryCode ? AuthAuditEvents.RecoveryUsed : AuthAuditEvents.TotpFailed,
                user.Id, user.Username, ip, userAgent,
                new { matched = false, locked = nowLocked, channel = "tui" }, cancellationToken).ConfigureAwait(false);
            return ServiceFail("Invalid code.");
        }

        await users.RecordLoginSuccessAsync(user.Id, ip, cancellationToken).ConfigureAwait(false);
        await audit.LogAsync(
            body.IsRecoveryCode ? AuthAuditEvents.RecoveryUsed : AuthAuditEvents.TotpVerified,
            user.Id, user.Username, ip, userAgent,
            new { channel = "tui" }, cancellationToken).ConfigureAwait(false);

        var (token, session) = await sessions.IssueAsync(
            user.Id, ip, userAgent, SessionLifetime, cancellationToken).ConfigureAwait(false);

        // TUI sessions are born elevated. Rationale: the operator just proved
        // TOTP, and they're physically at a console — exactly the threat model
        // step-up was designed to protect against in the browser (long-lived
        // cookies on a possibly-shared device). No need to re-prompt TOTP on
        // every destructive op. Web sessions stay basic-by-default.
        await sessions.ElevateAsync(session.Id, SessionLifetime, cancellationToken).ConfigureAwait(false);

        var result = new TuiLoginResult(
            Token: token,
            ExpiresAt: session.ExpiresAt,
            Username: user.Username,
            DisplayName: user.DisplayName);

        return Results.Ok(ServiceResponse<TuiLoginResult>.Ok(result, "Logged in."));
    }

    private static async Task<IResult> LogoutAsync(
        HttpContext ctx,
        ISessionService sessions,
        IAuthAuditService audit,
        CancellationToken cancellationToken)
    {
        // The session ID was placed on the principal by DaemonSessionAuthHandler
        // when it validated the X-NetFw-Session header. If it's missing, the
        // [Authorize] attribute wouldn't have let us in — but be defensive.
        var sessionIdClaim = ctx.User.FindFirst(DaemonSessionAuthHandler.SessionIdClaim)?.Value;
        if (!Guid.TryParse(sessionIdClaim, out var sessionId))
        {
            return Results.Ok(ServiceResponse<bool>.Fail("No active session."));
        }

        await sessions.RevokeAsync(sessionId, cancellationToken).ConfigureAwait(false);

        var userIdClaim = ctx.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
        Guid.TryParse(userIdClaim, out var userId);
        await audit.LogAsync(AuthAuditEvents.Logout,
            userId == Guid.Empty ? null : userId,
            ctx.User.Identity?.Name,
            ctx.Connection.RemoteIpAddress,
            "NetFirewall-TUI",
            ct: cancellationToken).ConfigureAwait(false);

        return Results.Ok(ServiceResponse<bool>.Ok(true, "Logged out."));
    }

    private static IResult ServiceFail(string message) =>
        Results.Ok(ServiceResponse<TuiLoginResult>.Fail(message));
}
