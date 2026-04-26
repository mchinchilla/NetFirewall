namespace NetFirewall.Services.Auth;

/// <summary>
/// Single-use TOTP recovery codes. Format <c>XXXXX-XXXXX</c> (10 base32-Crockford
/// chars + dash, ~50 bits each). Codes are returned in plaintext exactly once
/// at generation time; only Argon2 hashes persist.
/// </summary>
public interface IRecoveryCodeGenerator
{
    /// <summary>Generate <paramref name="count"/> fresh codes (default 10).</summary>
    IReadOnlyList<string> Generate(int count = 10);
}
