using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Services.Auth;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Auth;

/// <summary>
/// Real-Postgres coverage of <see cref="RecoveryCodeService"/>. Uses the real
/// Argon2 hasher and the real generator so the verify path exercises actual
/// crypto work — slower (~150–300 ms per Argon2 op) but the race-protection
/// test depends on the natural verify latency to widen the contention window.
///
/// We use small batches (count: 2–3) to keep wall-clock cost manageable —
/// generation itself is dominated by the per-code Argon2 hash.
/// </summary>
[Collection("Postgres")]
public sealed class RecoveryCodeServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private readonly Argon2PasswordHasher _hasher = new();
    private readonly RecoveryCodeGenerator _generator = new();
    private RecoveryCodeService _svc = null!;
    private Guid _userId;

    public RecoveryCodeServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _svc = new RecoveryCodeService(
            _pg.DataSource,
            _generator,
            _hasher,
            NullLogger<RecoveryCodeService>.Instance);
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

    private async Task<int> RawCountAsync(Guid userId, bool? usedFilter = null)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        var sql = "SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = @uid";
        if (usedFilter == true)  sql += " AND used_at IS NOT NULL";
        if (usedFilter == false) sql += " AND used_at IS NULL";
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("uid", userId);
        return Convert.ToInt32(await cmd.ExecuteScalarAsync());
    }

    /// <summary>Force a single existing code into the "used" state for the given user.</summary>
    private async Task MarkOneUsedAsync(Guid userId)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(@"
            UPDATE user_recovery_codes
               SET used_at = now()
             WHERE id = (SELECT id FROM user_recovery_codes
                          WHERE user_id = @uid AND used_at IS NULL
                          LIMIT 1)", conn);
        cmd.Parameters.AddWithValue("uid", userId);
        await cmd.ExecuteNonQueryAsync();
    }

    // ── Regenerate ─────────────────────────────────────────────────────

    [Fact]
    public async Task RegenerateAsync_ReturnsRequestedCount_AndPersistsHashes()
    {
        var codes = await _svc.RegenerateAsync(_userId, count: 3);

        Assert.Equal(3, codes.Count);
        // Plaintext is XXXXX-XXXXX shape (returned to user once).
        foreach (var code in codes) Assert.Matches(@"^[A-Z2-9]{5}-[A-Z2-9]{5}$", code);
        Assert.Equal(3, await RawCountAsync(_userId, usedFilter: false));
        Assert.Equal(0, await RawCountAsync(_userId, usedFilter: true));
    }

    [Fact]
    public async Task RegenerateAsync_OnlyHashesPersist_NotPlaintext()
    {
        var codes = await _svc.RegenerateAsync(_userId, count: 2);

        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT code_hash FROM user_recovery_codes WHERE user_id = @uid", conn);
        cmd.Parameters.AddWithValue("uid", _userId);
        await using var reader = await cmd.ExecuteReaderAsync();

        var stored = new List<string>();
        while (await reader.ReadAsync()) stored.Add(reader.GetString(0));

        // Stored entries are Argon2 encoded strings, not the plaintext.
        Assert.All(stored, h => Assert.StartsWith("$argon2id$", h));
        Assert.All(codes,  c => Assert.DoesNotContain(stored, h => h == c));
    }

    [Fact]
    public async Task RegenerateAsync_WipesPriorUnused_ButPreservesAlreadyUsed()
    {
        // First batch of 3, then mark one as used.
        await _svc.RegenerateAsync(_userId, count: 3);
        await MarkOneUsedAsync(_userId);
        Assert.Equal(2, await RawCountAsync(_userId, usedFilter: false));
        Assert.Equal(1, await RawCountAsync(_userId, usedFilter: true));

        // Regenerate — should wipe the 2 unused, leave the 1 used in place.
        await _svc.RegenerateAsync(_userId, count: 2);

        Assert.Equal(2, await RawCountAsync(_userId, usedFilter: false));
        Assert.Equal(1, await RawCountAsync(_userId, usedFilter: true));
    }

    [Fact]
    public async Task RegenerateAsync_OtherUsersUnaffected()
    {
        var bob = await SeedUserAsync("bob");
        await _svc.RegenerateAsync(bob, count: 3);
        await _svc.RegenerateAsync(_userId, count: 2);

        // Regenerating alice's set must not delete bob's.
        Assert.Equal(3, await RawCountAsync(bob, usedFilter: false));
        Assert.Equal(2, await RawCountAsync(_userId, usedFilter: false));
    }

    // ── CountUnused ────────────────────────────────────────────────────

    [Fact]
    public async Task CountUnusedAsync_OnEmpty_ReturnsZero()
    {
        Assert.Equal(0, await _svc.CountUnusedAsync(_userId));
    }

    [Fact]
    public async Task CountUnusedAsync_IgnoresUsedCodes()
    {
        await _svc.RegenerateAsync(_userId, count: 3);
        await MarkOneUsedAsync(_userId);

        Assert.Equal(2, await _svc.CountUnusedAsync(_userId));
    }

    // ── VerifyAndConsume ───────────────────────────────────────────────

    [Fact]
    public async Task VerifyAndConsumeAsync_HappyPath_ReturnsTrue_AndMarksUsed()
    {
        var codes = await _svc.RegenerateAsync(_userId, count: 2);
        var pick = codes[0];

        var ok = await _svc.VerifyAndConsumeAsync(_userId, pick);

        Assert.True(ok);
        Assert.Equal(1, await RawCountAsync(_userId, usedFilter: false));
        Assert.Equal(1, await RawCountAsync(_userId, usedFilter: true));
    }

    [Fact]
    public async Task VerifyAndConsumeAsync_SecondUseOfSameCode_ReturnsFalse()
    {
        var codes = await _svc.RegenerateAsync(_userId, count: 2);
        var pick = codes[0];

        Assert.True(await _svc.VerifyAndConsumeAsync(_userId, pick));
        Assert.False(await _svc.VerifyAndConsumeAsync(_userId, pick)); // single-use
    }

    [Fact]
    public async Task VerifyAndConsumeAsync_WrongCode_ReturnsFalse_AndConsumesNothing()
    {
        await _svc.RegenerateAsync(_userId, count: 2);

        var ok = await _svc.VerifyAndConsumeAsync(_userId, "WRONG-CODE!");

        Assert.False(ok);
        Assert.Equal(2, await RawCountAsync(_userId, usedFilter: false));
        Assert.Equal(0, await RawCountAsync(_userId, usedFilter: true));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\t")]
    public async Task VerifyAndConsumeAsync_EmptyOrWhitespace_ReturnsFalse_WithoutDbHit(string code)
    {
        await _svc.RegenerateAsync(_userId, count: 2);
        Assert.False(await _svc.VerifyAndConsumeAsync(_userId, code));
        Assert.Equal(2, await RawCountAsync(_userId, usedFilter: false)); // nothing consumed
    }

    [Fact]
    public async Task VerifyAndConsumeAsync_CodeBelongingToAnotherUser_DoesNotMatch()
    {
        var bob = await SeedUserAsync("bob");
        var bobCodes = await _svc.RegenerateAsync(bob, count: 2);
        await _svc.RegenerateAsync(_userId, count: 2);

        // Try alice's account with bob's code → reject (we only walk alice's hashes).
        var ok = await _svc.VerifyAndConsumeAsync(_userId, bobCodes[0]);

        Assert.False(ok);
        Assert.Equal(2, await RawCountAsync(bob, usedFilter: false));    // bob's intact
        Assert.Equal(2, await RawCountAsync(_userId, usedFilter: false)); // alice's intact
    }

    [Fact]
    public async Task VerifyAndConsumeAsync_NoCodesRegistered_ReturnsFalse()
    {
        // No RegenerateAsync called — empty set.
        Assert.False(await _svc.VerifyAndConsumeAsync(_userId, "ANY-CODE"));
    }

    // ── Race protection ────────────────────────────────────────────────

    [Fact]
    public async Task VerifyAndConsumeAsync_TwoConcurrentConsumes_OnlyOneSucceeds()
    {
        // The window between hash-verify and the UPDATE is wide (Argon2 ~150 ms).
        // The service guards against double-consume with `WHERE used_at IS NULL`
        // + checking the rowcount returned by UPDATE.
        var codes = await _svc.RegenerateAsync(_userId, count: 2);
        var pick = codes[0];

        var task1 = _svc.VerifyAndConsumeAsync(_userId, pick);
        var task2 = _svc.VerifyAndConsumeAsync(_userId, pick);
        var results = await Task.WhenAll(task1, task2);

        Assert.Equal(1, results.Count(r => r));   // exactly one success
        Assert.Equal(1, results.Count(r => !r));  // exactly one race-loser
        Assert.Equal(1, await RawCountAsync(_userId, usedFilter: true));   // one consumed
        Assert.Equal(1, await RawCountAsync(_userId, usedFilter: false));  // other untouched
    }
}
