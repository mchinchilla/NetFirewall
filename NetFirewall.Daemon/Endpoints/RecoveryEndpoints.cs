using Microsoft.AspNetCore.Mvc;
using NetFirewall.Daemon.Auth;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Auth;

namespace NetFirewall.Daemon.Endpoints;

/// <summary>
/// Recovery surface for locked-out / lost-TOTP scenarios. Reachable ONLY when
/// the connecting Unix-socket peer is root (UID 0) — see
/// <see cref="DaemonRequireRootPeerAttribute"/>. The TUI invokes these
/// endpoints when the operator is sitting at the console with sudo, has lost
/// access to the Web (forgot password / lost TOTP device / locked self out),
/// and needs to break glass.
///
/// <para>Every action also clears the lockout state so the user can log in
/// immediately afterwards. Each call lands in <c>auth_audit_log</c> with the
/// channel set to <c>tui-recovery</c> for visibility.</para>
/// </summary>
public static class RecoveryEndpoints
{
    public static void MapRecoveryEndpoints(this IEndpointRouteBuilder app)
    {
        // All recovery endpoints share the root-peer gate + AllowAnonymous.
        // The standard session header path doesn't apply here — that's the
        // whole point of recovery (no working session to authenticate with).
        var grp = app.MapGroup("/v1/auth/recovery");

        grp.MapGet("/users", ListUsersAsync)
            .AllowAnonymous()
            .WithMetadata(new DaemonRequireRootPeerAttribute());

        grp.MapPost("/reset-password", ResetPasswordAsync)
            .AllowAnonymous()
            .WithMetadata(new DaemonRequireRootPeerAttribute());

        grp.MapPost("/disable-totp", DisableTotpAsync)
            .AllowAnonymous()
            .WithMetadata(new DaemonRequireRootPeerAttribute());
    }

    private static async Task<IResult> ListUsersAsync(
        IUserService users,
        IUserTotpService totp,
        CancellationToken ct)
    {
        var all = await users.ListAsync(ct);
        var now = DateTimeOffset.UtcNow;
        // We need a TOTP-presence flag per user. ListAsync returns the user
        // rows; HasEnrolledAsync hits dhcp_user_totp_secrets one at a time.
        // For an admin recovery picker (typically <100 users) this is fine —
        // serial calls with HTTP keep-alive on the daemon's pool. If this ever
        // gets slow we'd add a single JOIN query instead.
        var summaries = new List<RecoveryUserSummary>(all.Count);
        foreach (var u in all)
        {
            var hasTotp = await totp.HasEnrolledAsync(u.Id, ct);
            summaries.Add(new RecoveryUserSummary(
                Id: u.Id,
                Username: u.Username,
                DisplayName: u.DisplayName,
                Role: u.Role,
                IsActive: u.IsActive,
                IsLocked: u.LockedUntil is { } until && until > now,
                HasTotp: hasTotp));
        }

        return Results.Json(ServiceResponse<IReadOnlyList<RecoveryUserSummary>>.Ok(summaries));
    }

    private static async Task<IResult> ResetPasswordAsync(
        [FromBody] RecoveryResetPasswordRequest body,
        IUserService users,
        IPasswordHasher hasher,
        IAuthAuditService audit,
        HttpContext ctx,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(body.Username))
            return Fail("Username is required.");
        if (string.IsNullOrEmpty(body.NewPassword) || body.NewPassword.Length < 8)
            return Fail("Password must be at least 8 characters.");

        var user = await users.GetByUsernameAsync(body.Username, ct);
        if (user is null)
            return Fail($"User '{body.Username}' not found.");

        var newHash = await hasher.HashAsync(body.NewPassword, ct);
        await users.UpdatePasswordHashAsync(user.Id, newHash, ct);
        await users.ClearLockoutAsync(user.Id, ct);

        await audit.LogAsync(
            "auth.recovery.password_reset",
            userId: user.Id, username: user.Username,
            ip: ctx.Connection.RemoteIpAddress,
            userAgent: ctx.Request.Headers.UserAgent.ToString(),
            detail: new { channel = "tui-recovery", lockoutCleared = true },
            ct: ct);

        return Results.Json(ServiceResponse<RecoveryActionResult>.Ok(
            new RecoveryActionResult(user.Username, "password_reset", LockoutCleared: true),
            "Password reset and lockout cleared."));
    }

    private static async Task<IResult> DisableTotpAsync(
        [FromBody] RecoveryDisableTotpRequest body,
        IUserService users,
        IUserTotpService totp,
        IAuthAuditService audit,
        HttpContext ctx,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(body.Username))
            return Fail("Username is required.");

        var user = await users.GetByUsernameAsync(body.Username, ct);
        if (user is null)
            return Fail($"User '{body.Username}' not found.");

        // ResetAsync is a no-op if the user wasn't enrolled — safe to call
        // unconditionally. Lockout-clearing accompanies it because TOTP-fail
        // lockouts are the most common reason to be here.
        await totp.ResetAsync(user.Id, ct);
        await users.ClearLockoutAsync(user.Id, ct);

        await audit.LogAsync(
            "auth.recovery.totp_disabled",
            userId: user.Id, username: user.Username,
            ip: ctx.Connection.RemoteIpAddress,
            userAgent: ctx.Request.Headers.UserAgent.ToString(),
            detail: new { channel = "tui-recovery", lockoutCleared = true },
            ct: ct);

        return Results.Json(ServiceResponse<RecoveryActionResult>.Ok(
            new RecoveryActionResult(user.Username, "totp_disabled", LockoutCleared: true),
            "TOTP disabled. The user must re-enroll on next Web login."));
    }

    private static IResult Fail(string message) =>
        Results.Json(ServiceResponse<RecoveryActionResult>.Fail(message));
}
