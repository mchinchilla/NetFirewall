using System.Net;
using RepoDb.Attributes;

namespace NetFirewall.Models.Auth;

[Map("user_sessions")]
public class UserSession
{
    [Map("id")]              public Guid Id { get; set; }
    [Map("user_id")]         public Guid UserId { get; set; }

    /// <summary>SHA-256 hex of the cookie token. Plaintext token never persists.</summary>
    [Map("token_hash")]      public string TokenHash { get; set; } = string.Empty;

    [Map("auth_level")]      public string AuthLevel { get; set; } = AuthLevels.Basic;
    [Map("elevated_until")]  public DateTimeOffset? ElevatedUntil { get; set; }
    [Map("created_at")]      public DateTimeOffset CreatedAt { get; set; }
    [Map("expires_at")]      public DateTimeOffset ExpiresAt { get; set; }
    [Map("last_seen_at")]    public DateTimeOffset LastSeenAt { get; set; }
    [Map("ip")]              public IPAddress? Ip { get; set; }
    [Map("user_agent")]      public string? UserAgent { get; set; }
    [Map("revoked_at")]      public DateTimeOffset? RevokedAt { get; set; }

    public bool IsActive(DateTimeOffset now)
        => RevokedAt is null && now < ExpiresAt;

    public bool IsElevated(DateTimeOffset now)
        => AuthLevel == AuthLevels.Elevated && ElevatedUntil is { } until && now < until;
}

public static class AuthLevels
{
    public const string Basic    = "basic";
    public const string Elevated = "elevated";
}
