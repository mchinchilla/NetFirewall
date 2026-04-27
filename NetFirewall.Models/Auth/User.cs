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

    // ---- Profile ---- (migration 00017)
    [Map("first_name")]         public string? FirstName { get; set; }
    [Map("last_name")]          public string? LastName { get; set; }
    [Map("display_name")]       public string? DisplayName { get; set; }
    [Map("phone")]              public string? Phone { get; set; }
    [Map("timezone")]           public string? Timezone { get; set; } = "UTC";
    [Map("locale")]             public string? Locale { get; set; } = "en";

    /// <summary>
    /// Best label to show in UI: explicit DisplayName → "First Last" → username.
    /// Centralized so every view picks the same fallback.
    /// </summary>
    public string EffectiveDisplayName
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(DisplayName)) return DisplayName!;
            var combined = $"{FirstName} {LastName}".Trim();
            return string.IsNullOrEmpty(combined) ? Username : combined;
        }
    }

    /// <summary>2-char initials from EffectiveDisplayName for avatar circles.</summary>
    public string Initials
    {
        get
        {
            var n = EffectiveDisplayName.Trim();
            if (string.IsNullOrEmpty(n)) return "?";
            var parts = n.Split(new[] { ' ', '\t', '_', '-', '.' },
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length >= 2)
                return ($"{parts[0][0]}{parts[1][0]}").ToUpperInvariant();
            return parts[0].Length >= 2
                ? parts[0].Substring(0, 2).ToUpperInvariant()
                : parts[0].Substring(0, 1).ToUpperInvariant();
        }
    }
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
