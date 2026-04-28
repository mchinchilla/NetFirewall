using System.Security.Cryptography;
using Moq;
using NetFirewall.Web.Auth;
using NetFirewall.Web.Daemon;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// Thin proxy over <see cref="IDaemonClient"/>. The whole point is "this class
/// does nothing but delegate" — tests pin that property so a future refactor
/// (e.g. adding a local cache or a fallback to the AES cipher) is intentional
/// rather than accidental.
/// </summary>
public class DaemonTotpSecretCipherTests
{
    private readonly Mock<IDaemonClient> _daemon = new();

    private DaemonTotpSecretCipher Create() => new(_daemon.Object);

    [Fact]
    public async Task EncryptAsync_DelegatesToDaemon_AndReturnsItsBytes()
    {
        var plaintext = new byte[] { 1, 2, 3, 4, 5 };
        var cipherBytes = new byte[] { 9, 8, 7 };
        _daemon.Setup(d => d.EncryptTotpAsync(plaintext, It.IsAny<CancellationToken>()))
               .ReturnsAsync(cipherBytes);

        var result = await Create().EncryptAsync(plaintext);

        Assert.Equal(cipherBytes, result);
        _daemon.Verify(d => d.EncryptTotpAsync(plaintext, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task DecryptAsync_DelegatesToDaemon_AndReturnsItsBytes()
    {
        var cipherBytes = new byte[] { 9, 8, 7 };
        var plaintext = new byte[] { 1, 2, 3 };
        _daemon.Setup(d => d.DecryptTotpAsync(cipherBytes, It.IsAny<CancellationToken>()))
               .ReturnsAsync(plaintext);

        var result = await Create().DecryptAsync(cipherBytes);

        Assert.Equal(plaintext, result);
        _daemon.Verify(d => d.DecryptTotpAsync(cipherBytes, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task EncryptAsync_DaemonThrows_ExceptionPropagates()
    {
        // Required so callers (UserTotpService.EnrollAsync) see the failure
        // and can surface it. Eating the exception would persist a corrupt
        // empty/null secret instead.
        _daemon.Setup(d => d.EncryptTotpAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
               .ThrowsAsync(new InvalidOperationException("daemon unreachable"));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => Create().EncryptAsync(new byte[] { 1, 2, 3 }));
    }

    [Fact]
    public async Task DecryptAsync_DaemonThrows_ExceptionPropagates()
    {
        // Required: UserTotpService catches the throw and returns false to
        // the caller (login/verify path), which surfaces as "code does not
        // match" instead of a 500.
        _daemon.Setup(d => d.DecryptTotpAsync(It.IsAny<byte[]>(), It.IsAny<CancellationToken>()))
               .ThrowsAsync(new CryptographicException("master key wrong"));

        await Assert.ThrowsAsync<CryptographicException>(
            () => Create().DecryptAsync(new byte[] { 1, 2, 3 }));
    }

    [Fact]
    public async Task EncryptAsync_PassesCancellationTokenThroughToDaemon()
    {
        using var cts = new CancellationTokenSource();
        _daemon.Setup(d => d.EncryptTotpAsync(It.IsAny<byte[]>(), cts.Token))
               .ReturnsAsync(Array.Empty<byte>());

        await Create().EncryptAsync(new byte[] { 1 }, cts.Token);

        _daemon.Verify(d => d.EncryptTotpAsync(It.IsAny<byte[]>(), cts.Token), Times.Once);
    }
}
