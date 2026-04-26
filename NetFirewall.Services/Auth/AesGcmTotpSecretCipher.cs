using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace NetFirewall.Services.Auth;

/// <summary>
/// AES-256-GCM cipher for TOTP secrets. Key source priority:
///   1. <c>NETFIREWALL_MASTER_KEY</c> environment variable (base64, 32 bytes).
///   2. <c>Auth:MasterKey</c> in configuration (Development only — never production).
///   3. (Development only) auto-generated ephemeral key with a loud warning;
///       data encrypted with that key is unrecoverable across restarts.
/// In production the daemon (Phase 2.1) supplies the key via systemd-creds.
/// </summary>
public sealed class AesGcmTotpSecretCipher : ITotpSecretCipher
{
    private const int NonceSize = 12;   // GCM standard
    private const int TagSize = 16;     // GCM standard
    private const int KeySize = 32;     // AES-256

    private readonly byte[] _key;

    public AesGcmTotpSecretCipher(IConfiguration configuration, IHostEnvironment env, ILogger<AesGcmTotpSecretCipher> logger)
    {
        var fromEnv = Environment.GetEnvironmentVariable("NETFIREWALL_MASTER_KEY");
        var fromCfg = configuration["Auth:MasterKey"];

        var raw = !string.IsNullOrEmpty(fromEnv) ? fromEnv : fromCfg;
        if (!string.IsNullOrEmpty(raw))
        {
            byte[] decoded;
            try { decoded = Convert.FromBase64String(raw); }
            catch { throw new InvalidOperationException("NETFIREWALL_MASTER_KEY is not valid base64."); }
            if (decoded.Length != KeySize)
                throw new InvalidOperationException($"NETFIREWALL_MASTER_KEY must decode to exactly {KeySize} bytes (AES-256).");

            _key = decoded;
            logger.LogInformation("TOTP cipher: using configured master key ({Source})",
                !string.IsNullOrEmpty(fromEnv) ? "env" : "config");
            return;
        }

        if (!env.IsDevelopment())
            throw new InvalidOperationException(
                "NETFIREWALL_MASTER_KEY is required in non-Development environments. " +
                "Generate one with: openssl rand -base64 32");

        _key = RandomNumberGenerator.GetBytes(KeySize);
        logger.LogWarning(
            "TOTP cipher: NETFIREWALL_MASTER_KEY missing; generated an EPHEMERAL key for this Development run. " +
            "All TOTP secrets persisted now will become unrecoverable on restart. " +
            "Set NETFIREWALL_MASTER_KEY=$(openssl rand -base64 32) to persist.");
    }

    public byte[] Encrypt(ReadOnlySpan<byte> plaintext)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[TagSize];

        using var gcm = new AesGcm(_key, TagSize);
        gcm.Encrypt(nonce, plaintext, ciphertext, tag);

        // Layout: nonce || tag || ciphertext
        var result = new byte[NonceSize + TagSize + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, result, 0, NonceSize);
        Buffer.BlockCopy(tag, 0, result, NonceSize, TagSize);
        Buffer.BlockCopy(ciphertext, 0, result, NonceSize + TagSize, ciphertext.Length);
        return result;
    }

    public byte[] Decrypt(ReadOnlySpan<byte> blob)
    {
        if (blob.Length < NonceSize + TagSize)
            throw new CryptographicException("TOTP ciphertext is too short to contain nonce+tag.");

        var nonce = blob.Slice(0, NonceSize);
        var tag = blob.Slice(NonceSize, TagSize);
        var ciphertext = blob.Slice(NonceSize + TagSize);
        var plaintext = new byte[ciphertext.Length];

        using var gcm = new AesGcm(_key, TagSize);
        gcm.Decrypt(nonce, ciphertext, tag, plaintext); // throws on tampering / wrong key
        return plaintext;
    }
}

