using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Services.Auth;
using Xunit;

namespace NetFirewall.Tests.Auth;

[Collection("EnvVarSerial")] // serializes tests that mutate process env vars
public class AesGcmTotpSecretCipherTests : IDisposable
{
    private const string MasterKeyEnv = "NETFIREWALL_MASTER_KEY";
    private readonly string? _originalEnv;

    public AesGcmTotpSecretCipherTests()
    {
        _originalEnv = Environment.GetEnvironmentVariable(MasterKeyEnv);
        Environment.SetEnvironmentVariable(MasterKeyEnv, null);
    }

    public void Dispose() =>
        Environment.SetEnvironmentVariable(MasterKeyEnv, _originalEnv);

    private static AesGcmTotpSecretCipher CreateWithKey(byte[] key, string envName = "Production")
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Auth:MasterKey"] = Convert.ToBase64String(key)
            })
            .Build();
        var env = new Mock<IHostEnvironment>();
        env.SetupGet(e => e.EnvironmentName).Returns(envName);
        return new AesGcmTotpSecretCipher(config, env.Object, NullLogger<AesGcmTotpSecretCipher>.Instance);
    }

    private static AesGcmTotpSecretCipher CreateInDevWithoutKey()
    {
        var config = new ConfigurationBuilder().Build();
        var env = new Mock<IHostEnvironment>();
        env.SetupGet(e => e.EnvironmentName).Returns("Development");
        return new AesGcmTotpSecretCipher(config, env.Object, NullLogger<AesGcmTotpSecretCipher>.Instance);
    }

    private static byte[] RandomKey(int size = 32) => RandomNumberGenerator.GetBytes(size);

    [Fact]
    public async Task EncryptThenDecrypt_RoundTripsPlaintext()
    {
        var cipher = CreateWithKey(RandomKey());
        var plaintext = Encoding.UTF8.GetBytes("the quick brown fox jumps over the lazy dog");

        var blob = await cipher.EncryptAsync(plaintext);
        var roundtrip = await cipher.DecryptAsync(blob);

        Assert.Equal(plaintext, roundtrip);
    }

    [Fact]
    public async Task Encrypt_EmitsLayoutOfNoncePlusTagPlusCiphertext()
    {
        var cipher = CreateWithKey(RandomKey());
        var plaintext = new byte[20]; // typical TOTP secret length

        var blob = await cipher.EncryptAsync(plaintext);

        // 12-byte nonce + 16-byte tag + ciphertext (same length as plaintext for GCM)
        Assert.Equal(12 + 16 + plaintext.Length, blob.Length);
    }

    [Fact]
    public async Task Encrypt_ProducesDifferentCiphertextEachCall()
    {
        var cipher = CreateWithKey(RandomKey());
        var plaintext = Encoding.UTF8.GetBytes("hello");

        var a = await cipher.EncryptAsync(plaintext);
        var b = await cipher.EncryptAsync(plaintext);

        Assert.NotEqual(a, b); // random nonce → different output
    }

    [Fact]
    public async Task Decrypt_ThrowsWhenTagIsTampered()
    {
        var cipher = CreateWithKey(RandomKey());
        var blob = await cipher.EncryptAsync(Encoding.UTF8.GetBytes("secret"));

        // Flip a bit in the auth tag (offset 12..28).
        blob[15] ^= 0x01;

        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(
            () => cipher.DecryptAsync(blob));
    }

    [Fact]
    public async Task Decrypt_ThrowsWhenCiphertextIsTampered()
    {
        var cipher = CreateWithKey(RandomKey());
        var blob = await cipher.EncryptAsync(Encoding.UTF8.GetBytes("secret"));

        // Flip a bit in the ciphertext region (offset 28..end).
        blob[^1] ^= 0x01;

        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(
            () => cipher.DecryptAsync(blob));
    }

    [Fact]
    public async Task Decrypt_ThrowsWhenKeyIsDifferent()
    {
        var cipherA = CreateWithKey(RandomKey());
        var blob = await cipherA.EncryptAsync(Encoding.UTF8.GetBytes("secret"));

        var cipherB = CreateWithKey(RandomKey()); // different key
        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(
            () => cipherB.DecryptAsync(blob));
    }

    [Fact]
    public async Task Decrypt_ThrowsWhenBlobIsTooShortForNonceAndTag()
    {
        var cipher = CreateWithKey(RandomKey());
        var blob = new byte[10]; // < 12 + 16

        await Assert.ThrowsAsync<CryptographicException>(
            () => cipher.DecryptAsync(blob));
    }

    [Fact]
    public void Constructor_ThrowsWhenKeyMissingInProduction()
    {
        var config = new ConfigurationBuilder().Build();
        var env = new Mock<IHostEnvironment>();
        env.SetupGet(e => e.EnvironmentName).Returns("Production");

        var ex = Assert.Throws<InvalidOperationException>(
            () => new AesGcmTotpSecretCipher(config, env.Object, NullLogger<AesGcmTotpSecretCipher>.Instance));
        Assert.Contains("NETFIREWALL_MASTER_KEY", ex.Message);
    }

    [Fact]
    public void Constructor_ThrowsWhenKeyIsInvalidBase64()
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Auth:MasterKey"] = "@@@not-base64@@@"
            })
            .Build();
        var env = new Mock<IHostEnvironment>();
        env.SetupGet(e => e.EnvironmentName).Returns("Production");

        var ex = Assert.Throws<InvalidOperationException>(
            () => new AesGcmTotpSecretCipher(config, env.Object, NullLogger<AesGcmTotpSecretCipher>.Instance));
        Assert.Contains("base64", ex.Message);
    }

    [Theory]
    [InlineData(16)] // AES-128 key size, but cipher requires AES-256
    [InlineData(24)] // AES-192
    [InlineData(31)]
    [InlineData(33)]
    public void Constructor_ThrowsWhenKeyIsWrongSize(int sizeBytes)
    {
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Auth:MasterKey"] = Convert.ToBase64String(RandomKey(sizeBytes))
            })
            .Build();
        var env = new Mock<IHostEnvironment>();
        env.SetupGet(e => e.EnvironmentName).Returns("Production");

        var ex = Assert.Throws<InvalidOperationException>(
            () => new AesGcmTotpSecretCipher(config, env.Object, NullLogger<AesGcmTotpSecretCipher>.Instance));
        Assert.Contains("32 bytes", ex.Message);
    }

    [Fact]
    public async Task Constructor_GeneratesEphemeralKeyInDevelopmentWhenAbsent()
    {
        var cipher = CreateInDevWithoutKey(); // no env, no config, env=Development
        var plaintext = Encoding.UTF8.GetBytes("dev secret");

        // Should still work — round-trip with the ephemeral key inside.
        var blob = await cipher.EncryptAsync(plaintext);
        var roundtrip = await cipher.DecryptAsync(blob);

        Assert.Equal(plaintext, roundtrip);
    }

    [Fact]
    public async Task EnvironmentVariable_TakesPrecedenceOverConfiguration()
    {
        var envKey = RandomKey();
        var configKey = RandomKey();
        Environment.SetEnvironmentVariable(MasterKeyEnv, Convert.ToBase64String(envKey));

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Auth:MasterKey"] = Convert.ToBase64String(configKey)
            })
            .Build();
        var env = new Mock<IHostEnvironment>();
        env.SetupGet(e => e.EnvironmentName).Returns("Production");

        var cipherUsingEnv = new AesGcmTotpSecretCipher(config, env.Object, NullLogger<AesGcmTotpSecretCipher>.Instance);
        var blob = await cipherUsingEnv.EncryptAsync(Encoding.UTF8.GetBytes("x"));

        // A second cipher built only from the config key (env unset) should NOT be
        // able to decrypt — confirming the env-var path won.
        Environment.SetEnvironmentVariable(MasterKeyEnv, null);
        var cipherUsingConfig = new AesGcmTotpSecretCipher(config, env.Object, NullLogger<AesGcmTotpSecretCipher>.Instance);

        await Assert.ThrowsAsync<AuthenticationTagMismatchException>(
            () => cipherUsingConfig.DecryptAsync(blob));
    }
}

[CollectionDefinition("EnvVarSerial", DisableParallelization = true)]
public class EnvVarSerialCollection { }
