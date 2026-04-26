namespace NetFirewall.Services.Auth;

/// <summary>
/// Authenticated encryption for TOTP shared secrets. The master key lives in
/// the daemon's environment (NETFIREWALL_MASTER_KEY) — the Web app, even if
/// it has DB access, cannot decrypt secrets without going through this service.
/// Once the daemon is in place this implementation moves there and the Web
/// gets a thin RPC client; the abstraction stays the same.
/// </summary>
public interface ITotpSecretCipher
{
    /// <summary>Encrypt a TOTP secret. Output: 12-byte nonce || 16-byte tag || ciphertext.</summary>
    byte[] Encrypt(ReadOnlySpan<byte> plaintext);

    /// <summary>Decrypt a previously-encrypted secret. Throws if tampered or wrong key.</summary>
    byte[] Decrypt(ReadOnlySpan<byte> ciphertext);
}
