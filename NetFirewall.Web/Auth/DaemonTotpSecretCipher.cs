using NetFirewall.Services.Auth;
using NetFirewall.Services.Daemon;

namespace NetFirewall.Web.Auth;

/// <summary>
/// <see cref="ITotpSecretCipher"/> that proxies every encrypt/decrypt to the
/// netfirewall-daemon over the Unix socket. The master key never touches
/// this process — a Web compromise (which has zero capabilities and a tiny
/// blast radius) can no longer decrypt stored TOTP secrets.
///
/// Failure mode: if the daemon is down, enrollment and TOTP verification
/// both fail loudly. UserTotpService catches the decrypt path; enrollment
/// surfaces the error to the user.
/// </summary>
public sealed class DaemonTotpSecretCipher : ITotpSecretCipher
{
    private readonly IDaemonClient _daemon;

    public DaemonTotpSecretCipher(IDaemonClient daemon) => _daemon = daemon;

    public Task<byte[]> EncryptAsync(byte[] plaintext, CancellationToken ct = default)
        => _daemon.EncryptTotpAsync(plaintext, ct);

    public Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken ct = default)
        => _daemon.DecryptTotpAsync(ciphertext, ct);
}
