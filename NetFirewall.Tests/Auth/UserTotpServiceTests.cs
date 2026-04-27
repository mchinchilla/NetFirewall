using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Services.Auth;
using NetFirewall.Tests.Infra;
using Npgsql;
using OtpNet;
using Xunit;

namespace NetFirewall.Tests.Auth;

/// <summary>
/// Real-Postgres coverage for <see cref="UserTotpService"/>. We use the real
/// <see cref="TotpService"/> (already covered in-memory) and an identity-cipher
/// stand-in: cipher round-trip is exercised by <c>AesGcmTotpSecretCipherTests</c>
/// already, and the identity fake lets us craft predictable secret bytes.
/// </summary>
[Collection("Postgres")]
public sealed class UserTotpServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private readonly TotpService _totp = new();
    private IdentityCipher _cipher = null!;
    private UserTotpService _svc = null!;
    private Guid _userId;

    public UserTotpServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _cipher = new IdentityCipher();
        _svc = new UserTotpService(_pg.DataSource, _totp, _cipher, NullLogger<UserTotpService>.Instance);
        _userId = await SeedUserAsync("alice");
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<Guid> SeedUserAsync(string username)
    {
        var id = Guid.NewGuid();
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "INSERT INTO users (id, username, password_hash) VALUES (@id, @u, 'x')", conn);
        cmd.Parameters.AddWithValue("id", id);
        cmd.Parameters.AddWithValue("u", username);
        await cmd.ExecuteNonQueryAsync();
        return id;
    }

    private static string CurrentCode(byte[] secret) =>
        new Totp(secret, step: 30, totpSize: 6).ComputeTotp(DateTimeOffset.UtcNow.UtcDateTime);

    /// <summary>
    /// Identity "encryption" — round-trips bytes verbatim, lets tests assert
    /// against known plaintext. Behavior of real AES-GCM lives elsewhere.
    /// </summary>
    private sealed class IdentityCipher : ITotpSecretCipher
    {
        public bool ForceDecryptFailure { get; set; }
        public Task<byte[]> EncryptAsync(byte[] plaintext, CancellationToken ct = default) =>
            Task.FromResult((byte[])plaintext.Clone());
        public Task<byte[]> DecryptAsync(byte[] ciphertext, CancellationToken ct = default) =>
            ForceDecryptFailure
                ? Task.FromException<byte[]>(new System.Security.Cryptography.CryptographicException("forced"))
                : Task.FromResult((byte[])ciphertext.Clone());
    }

    // ── enrollment lifecycle ───────────────────────────────────────────

    [Fact]
    public async Task HasEnrolledAsync_FalseBeforeEnroll_TrueAfter()
    {
        Assert.False(await _svc.HasEnrolledAsync(_userId));
        await _svc.EnrollAsync(_userId, _totp.GenerateSecret());
        Assert.True(await _svc.HasEnrolledAsync(_userId));
    }

    [Fact]
    public async Task GetAsync_ReturnsNullBeforeEnroll()
    {
        Assert.Null(await _svc.GetAsync(_userId));
    }

    [Fact]
    public async Task EnrollAsync_PersistsCiphertext_AndStampsEnrolledAt()
    {
        var secret = _totp.GenerateSecret();
        await _svc.EnrollAsync(_userId, secret);

        var stored = await _svc.GetAsync(_userId);
        Assert.NotNull(stored);
        Assert.Equal(_userId, stored!.UserId);
        // IdentityCipher round-trips verbatim, so stored bytes equal the secret.
        Assert.Equal(secret, stored.SecretEncrypted);
        Assert.True(stored.EnrolledAt > DateTimeOffset.UtcNow.AddMinutes(-1));
        Assert.Null(stored.LastUsedAt);
        Assert.Null(stored.LastUsedStep);
    }

    [Fact]
    public async Task EnrollAsync_ReEnroll_OverwritesSecret_AndResetsReplayCounters()
    {
        var first = _totp.GenerateSecret();
        await _svc.EnrollAsync(_userId, first);
        // Use the secret once so last_used_at/step are populated.
        Assert.True(await _svc.VerifyAsync(_userId, CurrentCode(first)));
        Assert.NotNull((await _svc.GetAsync(_userId))!.LastUsedStep);

        var second = _totp.GenerateSecret();
        await _svc.EnrollAsync(_userId, second);

        var after = await _svc.GetAsync(_userId);
        Assert.Equal(second, after!.SecretEncrypted);
        Assert.Null(after.LastUsedAt);
        Assert.Null(after.LastUsedStep);
    }

    // ── verify / replay protection ─────────────────────────────────────

    [Fact]
    public async Task VerifyAsync_ValidCode_ReturnsTrue_AndAdvancesLastUsedStep()
    {
        var secret = _totp.GenerateSecret();
        await _svc.EnrollAsync(_userId, secret);

        var before = (await _svc.GetAsync(_userId))!;
        Assert.Null(before.LastUsedStep);

        var ok = await _svc.VerifyAsync(_userId, CurrentCode(secret));

        Assert.True(ok);
        var after = (await _svc.GetAsync(_userId))!;
        Assert.NotNull(after.LastUsedStep);
        Assert.NotNull(after.LastUsedAt);
    }

    [Fact]
    public async Task VerifyAsync_WrongCode_ReturnsFalse_AndDoesNotAdvanceCounter()
    {
        await _svc.EnrollAsync(_userId, _totp.GenerateSecret());

        var ok = await _svc.VerifyAsync(_userId, "000000"); // unlikely to match

        Assert.False(ok);
        Assert.Null((await _svc.GetAsync(_userId))!.LastUsedStep);
    }

    [Fact]
    public async Task VerifyAsync_ReplayOfSameCode_RejectedBySecondCall()
    {
        var secret = _totp.GenerateSecret();
        await _svc.EnrollAsync(_userId, secret);
        var code = CurrentCode(secret);

        Assert.True(await _svc.VerifyAsync(_userId, code));   // first use → OK
        Assert.False(await _svc.VerifyAsync(_userId, code));  // replay → rejected
    }

    [Fact]
    public async Task VerifyAsync_NotEnrolled_ReturnsFalse_NoThrow()
    {
        Assert.False(await _svc.VerifyAsync(_userId, "123456"));
    }

    [Fact]
    public async Task VerifyAsync_DecryptionFailure_LoggedAndReturnsFalse_NoThrow()
    {
        // Simulates daemon down or wrong master key.
        var secret = _totp.GenerateSecret();
        await _svc.EnrollAsync(_userId, secret);
        _cipher.ForceDecryptFailure = true;

        var ok = await _svc.VerifyAsync(_userId, CurrentCode(secret));

        Assert.False(ok);
        // Counter not advanced when decryption fails.
        Assert.Null((await _svc.GetAsync(_userId))!.LastUsedStep);
    }

    // ── reset ──────────────────────────────────────────────────────────

    [Fact]
    public async Task ResetAsync_DeletesTheRow()
    {
        await _svc.EnrollAsync(_userId, _totp.GenerateSecret());
        Assert.True(await _svc.HasEnrolledAsync(_userId));

        await _svc.ResetAsync(_userId);

        Assert.False(await _svc.HasEnrolledAsync(_userId));
        Assert.Null(await _svc.GetAsync(_userId));
    }

    [Fact]
    public async Task ResetAsync_OnUnenrolledUser_IsNoOp()
    {
        // No exception even when there's nothing to delete.
        await _svc.ResetAsync(_userId);
        Assert.False(await _svc.HasEnrolledAsync(_userId));
    }

    // ── multi-user isolation ───────────────────────────────────────────

    [Fact]
    public async Task EnrollmentScopedPerUser()
    {
        var bob = await SeedUserAsync("bob");
        await _svc.EnrollAsync(_userId, _totp.GenerateSecret());
        await _svc.EnrollAsync(bob, _totp.GenerateSecret());

        Assert.True(await _svc.HasEnrolledAsync(_userId));
        Assert.True(await _svc.HasEnrolledAsync(bob));

        await _svc.ResetAsync(_userId);

        Assert.False(await _svc.HasEnrolledAsync(_userId));
        Assert.True(await _svc.HasEnrolledAsync(bob)); // unaffected
    }
}
