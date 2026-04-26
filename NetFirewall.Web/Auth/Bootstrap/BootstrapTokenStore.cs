using System.Security.Cryptography;

namespace NetFirewall.Web.Auth.Bootstrap;

/// <summary>
/// Singleton holding the in-memory bootstrap token used to create the first
/// admin when the <c>users</c> table is empty. Token is generated at startup
/// (only if needed) and also written to <c>logs/bootstrap-token.txt</c> with
/// restrictive perms so a sysadmin can read it without DB access.
/// Single-use: <see cref="Consume"/> clears it.
/// </summary>
public interface IBootstrapTokenStore
{
    bool IsActive { get; }
    string? CurrentToken { get; }
    bool Verify(string token);
    void Consume();
    void Issue(string token);
}

public sealed class BootstrapTokenStore : IBootstrapTokenStore
{
    private string? _token;

    public bool IsActive => _token is not null;
    public string? CurrentToken => _token;

    public bool Verify(string token)
    {
        if (_token is null || string.IsNullOrEmpty(token)) return false;
        // Constant-time comparison.
        var a = System.Text.Encoding.UTF8.GetBytes(_token);
        var b = System.Text.Encoding.UTF8.GetBytes(token);
        return CryptographicOperations.FixedTimeEquals(a, b);
    }

    public void Consume() => _token = null;

    public void Issue(string token)
    {
        if (_token is not null) throw new InvalidOperationException("Bootstrap token already issued.");
        _token = token;
    }
}
