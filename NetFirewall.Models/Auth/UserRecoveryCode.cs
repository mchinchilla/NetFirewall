using RepoDb.Attributes;

namespace NetFirewall.Models.Auth;

[Map("user_recovery_codes")]
public class UserRecoveryCode
{
    [Map("id")]         public Guid Id { get; set; }
    [Map("user_id")]    public Guid UserId { get; set; }

    /// <summary>Argon2id hash of the plaintext recovery code.</summary>
    [Map("code_hash")]  public string CodeHash { get; set; } = string.Empty;

    [Map("used_at")]    public DateTimeOffset? UsedAt { get; set; }
    [Map("created_at")] public DateTimeOffset CreatedAt { get; set; }
}
