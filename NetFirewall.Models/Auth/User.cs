using System.Net;
using RepoDb.Attributes;

namespace NetFirewall.Models.Auth;

[Map("users")]
public class User
{
    [Map("id")]                 public Guid Id { get; set; }
    [Map("username")]           public string Username { get; set; } = string.Empty;
    [Map("email")]              public string? Email { get; set; }
    [Map("password_hash")]      public string PasswordHash { get; set; } = string.Empty;
    [Map("role")]               public string Role { get; set; } = UserRoles.Viewer;
    [Map("is_active")]          public bool IsActive { get; set; } = true;
    [Map("failed_login_count")] public int FailedLoginCount { get; set; }
    [Map("locked_until")]       public DateTimeOffset? LockedUntil { get; set; }
    [Map("last_login_at")]      public DateTimeOffset? LastLoginAt { get; set; }
    [Map("last_login_ip")]      public IPAddress? LastLoginIp { get; set; }
    [Map("created_at")]         public DateTimeOffset CreatedAt { get; set; }
    [Map("updated_at")]         public DateTimeOffset UpdatedAt { get; set; }
}

/// <summary>
/// Closed set of role identifiers. Reference these constants from authorization
/// attributes / policies — never inline the string. New roles require a CHECK
/// constraint update in Schema.sql.
/// </summary>
public static class UserRoles
{
    public const string Admin    = "admin";
    public const string Operator = "operator";
    public const string Viewer   = "viewer";

    public static IReadOnlyList<string> All { get; } = new[] { Admin, Operator, Viewer };

    public static bool IsValid(string role) => All.Contains(role);
}
