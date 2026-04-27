using System.Net;
using RepoDb.Attributes;

namespace NetFirewall.Models.Auth;

[Map("auth_audit_log")]
public class AuthAuditEntry
{
    [Map("id")]          public long Id { get; set; }
    [Map("occurred_at")] public DateTimeOffset OccurredAt { get; set; }
    [Map("user_id")]     public Guid? UserId { get; set; }
    [Map("username")]    public string? Username { get; set; }
    [Map("event_type")]  public string EventType { get; set; } = string.Empty;
    [Map("ip")]          public IPAddress? Ip { get; set; }
    [Map("user_agent")]  public string? UserAgent { get; set; }

    /// <summary>Free-form JSON details (failure reason, route IDs touched, etc.).</summary>
    [Map("detail")]      public string? Detail { get; set; }
}

/// <summary>Canonical event names. Reference from services rather than inlining.</summary>
public static class AuthAuditEvents
{
    public const string LoginSuccess     = "login.success";
    public const string LoginFailed      = "login.failed";
    public const string LoginLocked      = "login.locked";
    public const string Logout           = "logout";
    public const string TotpEnrolled     = "totp.enrolled";
    public const string TotpVerified     = "totp.verified";
    public const string TotpFailed       = "totp.failed";
    public const string TotpReplayed     = "totp.replayed";
    public const string RecoveryUsed     = "recovery.used";
    public const string RecoveryRegen    = "recovery.regenerated";
    public const string ElevationGranted = "elevation.granted";
    public const string ElevationDenied  = "elevation.denied";
    public const string PasswordChanged  = "password.changed";
    public const string SessionRevoked   = "session.revoked";
    public const string BootstrapUsed    = "bootstrap.used";
    public const string UserCreated      = "user.created";
    public const string UserDisabled     = "user.disabled";
    public const string ProfileUpdated   = "profile.updated";
}
