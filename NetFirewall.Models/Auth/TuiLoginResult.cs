namespace NetFirewall.Models.Auth;

/// <summary>
/// Successful login response from the daemon's <c>POST /v1/auth/login</c>
/// endpoint. The <see cref="Token"/> is returned exactly once — the TUI
/// holds it in memory for the lifetime of the process and presents it as
/// <c>X-NetFw-Session</c> on subsequent calls. Storing it on disk would
/// turn it into a long-lived credential that survives reboots; we
/// deliberately don't.
/// </summary>
public sealed record TuiLoginResult(
    string Token,
    DateTimeOffset ExpiresAt,
    string Username,
    string? DisplayName);

/// <summary>Request body for <c>POST /v1/auth/login</c>.</summary>
public sealed record TuiLoginRequest(
    string Username,
    string Password,
    string TotpOrRecoveryCode,
    bool IsRecoveryCode = false);
