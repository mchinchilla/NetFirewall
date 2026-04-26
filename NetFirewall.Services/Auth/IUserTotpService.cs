using NetFirewall.Models.Auth;

namespace NetFirewall.Services.Auth;

/// <summary>
/// User-scoped TOTP operations: enrollment, lookup, verification with replay
/// protection. Wraps the cipher + raw <see cref="ITotpService"/> + persistence
/// so callers (controllers, daemon) never see plaintext secrets.
/// </summary>
public interface IUserTotpService
{
    /// <summary>True iff the user has finished TOTP enrollment.</summary>
    Task<bool> HasEnrolledAsync(Guid userId, CancellationToken ct = default);

    /// <summary>Fetch the encrypted record for a user (or null).</summary>
    Task<UserTotpSecret?> GetAsync(Guid userId, CancellationToken ct = default);

    /// <summary>
    /// Persist a freshly-generated secret. Caller passes the raw bytes — they
    /// are encrypted before hitting the DB. <c>byte[]</c> rather than
    /// <c>ReadOnlySpan&lt;byte&gt;</c> because spans cannot cross async awaits.
    /// </summary>
    Task EnrollAsync(Guid userId, byte[] rawSecret, CancellationToken ct = default);

    /// <summary>
    /// Verify a 6-digit code against the user's stored secret. On success,
    /// advances <c>last_used_step</c> so the same code can't be replayed.
    /// </summary>
    Task<bool> VerifyAsync(Guid userId, string code, CancellationToken ct = default);

    /// <summary>Delete the user's TOTP secret (admin-only — forces re-enrollment).</summary>
    Task ResetAsync(Guid userId, CancellationToken ct = default);
}
