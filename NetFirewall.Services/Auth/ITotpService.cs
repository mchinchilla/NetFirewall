namespace NetFirewall.Services.Auth;

/// <summary>
/// RFC 6238 TOTP. Use to generate enrollment QR data and verify codes during
/// login / step-up. Verification is replay-protected: the caller passes the
/// last-accepted step, and codes from that step or earlier are rejected.
/// </summary>
public interface ITotpService
{
    /// <summary>Generate a fresh 20-byte (160-bit) random secret.</summary>
    byte[] GenerateSecret();

    /// <summary>Convert a raw secret to base32 (no padding) for manual entry.</summary>
    string ToBase32(ReadOnlySpan<byte> secret);

    /// <summary>
    /// Build a standard <c>otpauth://totp/...</c> URI for QR rendering.
    /// </summary>
    /// <param name="issuer">Display name (e.g. "NetFirewall").</param>
    /// <param name="account">Username or email.</param>
    Uri BuildEnrollmentUri(ReadOnlySpan<byte> secret, string issuer, string account);

    /// <summary>
    /// Verify a 6-digit code with ±1 step (=30s) of clock skew.
    /// Returns the matching step counter on success, <c>null</c> on failure.
    /// Pass <paramref name="lastUsedStep"/> from <c>user_totp_secrets.last_used_step</c>
    /// — codes from that step or earlier are rejected (replay protection).
    /// </summary>
    long? Verify(ReadOnlySpan<byte> secret, string code, long? lastUsedStep, DateTimeOffset now);
}
