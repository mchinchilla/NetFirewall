namespace NetFirewall.Models.Auth;

/// <summary>
/// Slim user view for the recovery picker — username + display name + lockout
/// state, no auth secrets. Returned by <c>GET /v1/auth/recovery/users</c>.
/// </summary>
public sealed record RecoveryUserSummary(
    Guid Id,
    string Username,
    string? DisplayName,
    string Role,
    bool IsActive,
    bool IsLocked,
    bool HasTotp);

/// <summary>Request body for <c>POST /v1/auth/recovery/reset-password</c>.</summary>
public sealed record RecoveryResetPasswordRequest(
    string Username,
    string NewPassword);

/// <summary>Request body for <c>POST /v1/auth/recovery/disable-totp</c>.</summary>
public sealed record RecoveryDisableTotpRequest(string Username);

/// <summary>Outcome of a recovery operation. <see cref="Username"/> is echoed back so the TUI can confirm the right account was touched.</summary>
public sealed record RecoveryActionResult(string Username, string Action, bool LockoutCleared);
