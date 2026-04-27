namespace NetFirewall.Services.Auth;

/// <summary>
/// Authenticated encryption for TOTP shared secrets.
///
/// In production the master key lives inside the netfirewall-daemon process
/// (NETFIREWALL_MASTER_KEY in its env file, mode 0600) and the Web speaks to
/// the daemon over the Unix socket via <see cref="DaemonTotpSecretCipher"/>.
/// In dev or single-process deployments <see cref="AesGcmTotpSecretCipher"/>
/// holds the key directly. Either way, callers see this interface — the swap
/// is a one-line DI change.
///
/// Methods are async because the daemon-backed implementation does HTTP-on-
/// Unix-socket; the local AES impl just wraps results in Task.FromResult.
/// </summary>
public interface ITotpSecretCipher
{
    /// <summary>Encrypt a TOTP secret. Output: 12-byte nonce || 16-byte tag || ciphertext.</summary>
    Task<byte[]> EncryptAsync(byte[] plaintext, CancellationToken ct = default);

    /// <summary>Decrypt a previously-encrypted secret. Throws if tampered or wrong key.</summary>
    Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken ct = default);
}
