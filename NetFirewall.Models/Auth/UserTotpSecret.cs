using RepoDb.Attributes;

namespace NetFirewall.Models.Auth;

[Map("user_totp_secrets")]
public class UserTotpSecret
{
    [Map("user_id")]          public Guid UserId { get; set; }

    /// <summary>
    /// AES-256-GCM ciphertext: 12-byte nonce || 16-byte tag || ciphertext.
    /// Decryption requires the daemon's master key (NETFIREWALL_MASTER_KEY).
    /// </summary>
    [Map("secret_encrypted")] public byte[] SecretEncrypted { get; set; } = Array.Empty<byte>();

    [Map("enrolled_at")]      public DateTimeOffset EnrolledAt { get; set; }
    [Map("last_used_at")]     public DateTimeOffset? LastUsedAt { get; set; }

    /// <summary>
    /// Most recent TOTP step counter accepted for this user. Same-window
    /// replays are rejected by requiring strictly greater on each verification.
    /// </summary>
    [Map("last_used_step")]   public long? LastUsedStep { get; set; }
}
