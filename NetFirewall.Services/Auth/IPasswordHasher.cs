namespace NetFirewall.Services.Auth;

/// <summary>
/// Argon2id password hashing. Encoded format is self-describing (parameters
/// embedded), so storage is one TEXT column and verification works across
/// future parameter upgrades.
/// </summary>
public interface IPasswordHasher
{
    /// <summary>Hash a plaintext password using current parameters.</summary>
    Task<string> HashAsync(string password, CancellationToken ct = default);

    /// <summary>
    /// Verify a plaintext against a stored encoded hash.
    /// Returns <c>(true, true)</c> on match-and-needs-rehash; the caller should
    /// re-hash with current parameters and persist.
    /// </summary>
    Task<PasswordVerificationResult> VerifyAsync(string password, string encodedHash, CancellationToken ct = default);
}

public readonly record struct PasswordVerificationResult(bool Matches, bool NeedsRehash);
