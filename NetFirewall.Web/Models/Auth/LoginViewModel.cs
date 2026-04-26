using System.ComponentModel.DataAnnotations;

namespace NetFirewall.Web.Models.Auth;

public sealed class LoginViewModel
{
    [Required, StringLength(64, MinimumLength = 1)]
    public string Username { get; set; } = string.Empty;

    [Required, DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    public string? ReturnUrl { get; set; }
}

public sealed class LoginTotpViewModel
{
    [Required, RegularExpression(@"^\d{6}$|^[A-Z2-9\-]{11}$",
        ErrorMessage = "Enter the 6-digit code from your authenticator, or a recovery code (XXXXX-XXXXX).")]
    public string Code { get; set; } = string.Empty;

    public bool IsRecoveryCode { get; set; }
    public string? ReturnUrl { get; set; }
}

public sealed class BootstrapViewModel
{
    [Required] public string Token { get; set; } = string.Empty;

    [Required, StringLength(64, MinimumLength = 3),
     RegularExpression(@"^[a-zA-Z0-9_.\-]+$", ErrorMessage = "Letters, digits, underscore, dot or dash.")]
    public string Username { get; set; } = string.Empty;

    [EmailAddress] public string? Email { get; set; }

    [Required, StringLength(128, MinimumLength = 12,
        ErrorMessage = "Password must be at least 12 characters.")]
    [DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    [Required, Compare(nameof(Password), ErrorMessage = "Passwords do not match.")]
    [DataType(DataType.Password)]
    public string ConfirmPassword { get; set; } = string.Empty;
}

public sealed class TotpEnrollViewModel
{
    /// <summary>Base32-encoded shared secret to render under the QR.</summary>
    public string SecretBase32 { get; set; } = string.Empty;

    /// <summary>Full otpauth:// URI for the QR.</summary>
    public string OtpAuthUri { get; set; } = string.Empty;

    /// <summary>Plaintext recovery codes — shown ONCE.</summary>
    public IReadOnlyList<string> RecoveryCodes { get; set; } = Array.Empty<string>();
}

public sealed class TotpEnrollConfirmViewModel
{
    [Required, RegularExpression(@"^\d{6}$",
        ErrorMessage = "Enter the 6-digit code from your authenticator app.")]
    public string Code { get; set; } = string.Empty;
}
