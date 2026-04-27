using System.ComponentModel.DataAnnotations;
using NetFirewall.Models.Auth;

namespace NetFirewall.Web.Models.Auth;

public sealed class ProfileFormViewModel
{
    // Read-only display
    public string Username { get; init; } = string.Empty;
    public string Role { get; init; } = string.Empty;
    public DateTimeOffset CreatedAt { get; init; }
    public DateTimeOffset? LastLoginAt { get; init; }

    [StringLength(80)] public string? FirstName { get; set; }
    [StringLength(80)] public string? LastName { get; set; }

    [StringLength(160)]
    public string? DisplayName { get; set; }

    [EmailAddress, StringLength(255)]
    public string? Email { get; set; }

    [StringLength(40)]
    [RegularExpression(@"^[\d\s\+\-\(\)\.]*$", ErrorMessage = "Phone may only contain digits, spaces, and + - ( ) .")]
    public string? Phone { get; set; }

    [StringLength(64)]
    public string? Timezone { get; set; } = "UTC";

    [StringLength(16)]
    public string? Locale { get; set; } = "en";

    public static ProfileFormViewModel FromUser(User u) => new()
    {
        Username     = u.Username,
        Role         = u.Role,
        CreatedAt    = u.CreatedAt,
        LastLoginAt  = u.LastLoginAt,
        FirstName    = u.FirstName,
        LastName     = u.LastName,
        DisplayName  = u.DisplayName,
        Email        = u.Email,
        Phone        = u.Phone,
        Timezone     = u.Timezone ?? "UTC",
        Locale       = u.Locale   ?? "en",
    };
}
