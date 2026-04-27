using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Auth;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Auth;

/// <summary>
/// Real-database coverage of <see cref="SessionService"/> — the in-memory
/// <c>SessionTokenHashingTests</c> class only covers the static helper.
/// Every test gets a fresh schema (so we can rely on user_sessions starting
/// empty) and a single seeded user to satisfy the FK.
/// </summary>
[Collection("Postgres")]
public sealed class SessionServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private SessionService _svc = null!;
    private Guid _userId;

    private static readonly TimeSpan BasicLifetime = TimeSpan.FromHours(8);

    public SessionServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _svc = new SessionService(_pg.DataSource, NullLogger<SessionService>.Instance);
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

    private async Task<UserSession> ReadSessionAsync(Guid sessionId)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand("SELECT * FROM user_sessions WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", sessionId);
        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync(), "session row missing");
        return new UserSession
        {
            Id = reader.GetGuid(reader.GetOrdinal("id")),
            UserId = reader.GetGuid(reader.GetOrdinal("user_id")),
            TokenHash = reader.GetString(reader.GetOrdinal("token_hash")),
            AuthLevel = reader.GetString(reader.GetOrdinal("auth_level")),
            ElevatedUntil = reader.IsDBNull(reader.GetOrdinal("elevated_until"))
                ? null : reader.GetFieldValue<DateTimeOffset>(reader.GetOrdinal("elevated_until")),
            CreatedAt = reader.GetFieldValue<DateTimeOffset>(reader.GetOrdinal("created_at")),
            ExpiresAt = reader.GetFieldValue<DateTimeOffset>(reader.GetOrdinal("expires_at")),
            LastSeenAt = reader.GetFieldValue<DateTimeOffset>(reader.GetOrdinal("last_seen_at")),
            RevokedAt = reader.IsDBNull(reader.GetOrdinal("revoked_at"))
                ? null : reader.GetFieldValue<DateTimeOffset>(reader.GetOrdinal("revoked_at"))
        };
    }

    private async Task SetExpiresAtAsync(Guid sessionId, DateTimeOffset newExpiry)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "UPDATE user_sessions SET expires_at = @e WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", sessionId);
        cmd.Parameters.AddWithValue("e", newExpiry);
        await cmd.ExecuteNonQueryAsync();
    }

    private async Task SetCreatedAtAsync(Guid sessionId, DateTimeOffset newCreated)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "UPDATE user_sessions SET created_at = @c WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", sessionId);
        cmd.Parameters.AddWithValue("c", newCreated);
        await cmd.ExecuteNonQueryAsync();
    }

    // ── Issue ──────────────────────────────────────────────────────────

    [Fact]
    public async Task IssueAsync_PersistsRowWithBasicLevel_AndHashedToken()
    {
        var (token, session) = await _svc.IssueAsync(
            _userId, IPAddress.Parse("10.0.0.5"), "ua-test", BasicLifetime);

        Assert.NotEmpty(token);
        Assert.Equal(AuthLevels.Basic, session.AuthLevel);
        Assert.Equal(_userId, session.UserId);
        Assert.NotEqual(Guid.Empty, session.Id);

        var stored = await ReadSessionAsync(session.Id);
        // Plaintext token must not equal the stored hash.
        Assert.NotEqual(token, stored.TokenHash);
        Assert.Equal(SessionService.HashToken(token), stored.TokenHash);
        // Expiry is roughly created + lifetime (allow ±5s for clock skew/test latency).
        var delta = stored.ExpiresAt - stored.CreatedAt;
        Assert.InRange(delta.TotalSeconds, BasicLifetime.TotalSeconds - 5, BasicLifetime.TotalSeconds + 5);
    }

    [Fact]
    public async Task IssueAsync_TwoCalls_ProduceDifferentTokens_AndDistinctRows()
    {
        var (t1, s1) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        var (t2, s2) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);

        Assert.NotEqual(t1, t2);
        Assert.NotEqual(s1.Id, s2.Id);
        Assert.NotEqual(s1.TokenHash, s2.TokenHash);
    }

    [Fact]
    public async Task IssueAsync_NullIpAndUserAgent_PersistAsDbNull()
    {
        var (_, session) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);

        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT ip IS NULL, user_agent IS NULL FROM user_sessions WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", session.Id);
        await using var r = await cmd.ExecuteReaderAsync();
        await r.ReadAsync();
        Assert.True(r.GetBoolean(0));
        Assert.True(r.GetBoolean(1));
    }

    // ── Validate (and sliding window) ──────────────────────────────────

    [Fact]
    public async Task ValidateAsync_HappyPath_ReturnsSession_AndSlidesBasicExpiry()
    {
        var (token, session) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        // Force the original expiry close to "now" so we can prove the slide.
        var nearExpiry = DateTimeOffset.UtcNow.AddMinutes(2);
        await SetExpiresAtAsync(session.Id, nearExpiry);

        var validated = await _svc.ValidateAsync(token, BasicLifetime);

        Assert.NotNull(validated);
        Assert.Equal(session.Id, validated!.Id);
        // Sliding: expires_at should now be ≈ now + BasicLifetime, not the near-expiry we forced.
        var now = DateTimeOffset.UtcNow;
        Assert.True(validated.ExpiresAt > now + BasicLifetime - TimeSpan.FromSeconds(5));
        Assert.True(validated.ExpiresAt < now + BasicLifetime + TimeSpan.FromSeconds(5));
        // last_seen_at also bumped.
        Assert.True(validated.LastSeenAt >= now - TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task ValidateAsync_ElevatedSession_DoesNotSlideExpiry()
    {
        var (token, session) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        await _svc.ElevateAsync(session.Id, TimeSpan.FromMinutes(15));
        // After elevation, give it a hard expiry 1 hour out.
        var hardExpiry = DateTimeOffset.UtcNow.AddHours(1);
        await SetExpiresAtAsync(session.Id, hardExpiry);

        var validated = await _svc.ValidateAsync(token, BasicLifetime);

        Assert.NotNull(validated);
        Assert.Equal(AuthLevels.Elevated, validated!.AuthLevel);
        // Elevated: hard cap preserved (not slid to now+BasicLifetime).
        var diff = (validated.ExpiresAt - hardExpiry).Duration();
        Assert.True(diff < TimeSpan.FromSeconds(2),
            $"expected expires_at ≈ {hardExpiry:O}, got {validated.ExpiresAt:O}");
    }

    [Fact]
    public async Task ValidateAsync_UnknownToken_ReturnsNull()
    {
        var result = await _svc.ValidateAsync("bogus-token-not-issued", BasicLifetime);
        Assert.Null(result);
    }

    [Fact]
    public async Task ValidateAsync_EmptyToken_ReturnsNullWithoutHittingDb()
    {
        Assert.Null(await _svc.ValidateAsync("", BasicLifetime));
    }

    [Fact]
    public async Task ValidateAsync_ExpiredSession_ReturnsNull_AndDoesNotResurrect()
    {
        var (token, session) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        // Force expired in the past.
        await SetExpiresAtAsync(session.Id, DateTimeOffset.UtcNow.AddMinutes(-5));

        Assert.Null(await _svc.ValidateAsync(token, BasicLifetime));

        // Sliding must NOT have happened — expires_at should still be in the past.
        var stored = await ReadSessionAsync(session.Id);
        Assert.True(stored.ExpiresAt < DateTimeOffset.UtcNow);
    }

    [Fact]
    public async Task ValidateAsync_RevokedSession_ReturnsNull()
    {
        var (token, session) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        await _svc.RevokeAsync(session.Id);

        Assert.Null(await _svc.ValidateAsync(token, BasicLifetime));
    }

    // ── Elevate ────────────────────────────────────────────────────────

    [Fact]
    public async Task ElevateAsync_FlipsLevelAndSetsElevatedUntil()
    {
        var (_, session) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);

        await _svc.ElevateAsync(session.Id, TimeSpan.FromMinutes(15));

        var stored = await ReadSessionAsync(session.Id);
        Assert.Equal(AuthLevels.Elevated, stored.AuthLevel);
        Assert.NotNull(stored.ElevatedUntil);
        var ttl = stored.ElevatedUntil!.Value - DateTimeOffset.UtcNow;
        Assert.InRange(ttl.TotalMinutes, 14, 16);
    }

    [Fact]
    public async Task ElevateAsync_RevokedSession_DoesNotChangeLevel()
    {
        var (_, session) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        await _svc.RevokeAsync(session.Id);

        await _svc.ElevateAsync(session.Id, TimeSpan.FromMinutes(15));

        var stored = await ReadSessionAsync(session.Id);
        Assert.Equal(AuthLevels.Basic, stored.AuthLevel); // untouched
        Assert.Null(stored.ElevatedUntil);
    }

    // ── Revoke ─────────────────────────────────────────────────────────

    [Fact]
    public async Task RevokeAsync_SetsRevokedAtTimestamp()
    {
        var (_, session) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        await _svc.RevokeAsync(session.Id);

        var stored = await ReadSessionAsync(session.Id);
        Assert.NotNull(stored.RevokedAt);
        Assert.True(stored.RevokedAt!.Value > DateTimeOffset.UtcNow.AddMinutes(-1));
    }

    [Fact]
    public async Task RevokeAsync_AlreadyRevoked_DoesNotOverwriteOriginalTimestamp()
    {
        var (_, session) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        await _svc.RevokeAsync(session.Id);
        var firstRevocation = (await ReadSessionAsync(session.Id)).RevokedAt;

        // Wait long enough that a new now() would be measurably different.
        await Task.Delay(50);
        await _svc.RevokeAsync(session.Id);

        var second = await ReadSessionAsync(session.Id);
        Assert.Equal(firstRevocation, second.RevokedAt); // idempotent — first revoke wins
    }

    [Fact]
    public async Task RevokeAllForUserAsync_RevokesActiveSessions_LeavesAlreadyRevokedAlone()
    {
        var (_, sActive1) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        var (_, sActive2) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        var (_, sAlready) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        await _svc.RevokeAsync(sAlready.Id);
        var alreadyTime = (await ReadSessionAsync(sAlready.Id)).RevokedAt;

        await Task.Delay(20);
        await _svc.RevokeAllForUserAsync(_userId);

        Assert.NotNull((await ReadSessionAsync(sActive1.Id)).RevokedAt);
        Assert.NotNull((await ReadSessionAsync(sActive2.Id)).RevokedAt);
        // Pre-revoked session keeps its original timestamp.
        Assert.Equal(alreadyTime, (await ReadSessionAsync(sAlready.Id)).RevokedAt);
    }

    [Fact]
    public async Task RevokeAllForUserAsync_OtherUsersUntouched()
    {
        var bob = await SeedUserAsync("bob");
        var (_, alice) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        var (_, bobSession) = await _svc.IssueAsync(bob, null, null, BasicLifetime);

        await _svc.RevokeAllForUserAsync(_userId);

        Assert.NotNull((await ReadSessionAsync(alice.Id)).RevokedAt);
        Assert.Null((await ReadSessionAsync(bobSession.Id)).RevokedAt);
    }

    // ── ListActive ─────────────────────────────────────────────────────

    [Fact]
    public async Task ListActiveAsync_ReturnsOnlyActiveSessions_OrderedByLastSeenDesc()
    {
        var (_, oldest)   = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        await Task.Delay(50);
        var (_, middle)   = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        await Task.Delay(50);
        var (_, newest)   = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        var (_, revoked)  = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        await _svc.RevokeAsync(revoked.Id);
        var (_, expired)  = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        await SetExpiresAtAsync(expired.Id, DateTimeOffset.UtcNow.AddMinutes(-1));

        var active = await _svc.ListActiveAsync(_userId);

        var ids = active.Select(s => s.Id).ToList();
        Assert.Equal(new[] { newest.Id, middle.Id, oldest.Id }, ids);
    }

    [Fact]
    public async Task ListActiveAsync_OnlyCurrentUserSessionsAreReturned()
    {
        var bob = await SeedUserAsync("bob");
        var (_, mine) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        await _svc.IssueAsync(bob, null, null, BasicLifetime);

        var active = await _svc.ListActiveAsync(_userId);

        Assert.Single(active);
        Assert.Equal(mine.Id, active[0].Id);
    }

    // ── Cleanup ────────────────────────────────────────────────────────

    [Fact]
    public async Task CleanupAsync_RemovesRevokedAndExpired_OlderThanCutoff()
    {
        var (_, oldRevoked) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        var (_, oldExpired) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        var (_, newRevoked) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        var (_, active)     = await _svc.IssueAsync(_userId, null, null, BasicLifetime);

        await _svc.RevokeAsync(oldRevoked.Id);
        await _svc.RevokeAsync(newRevoked.Id);
        await SetExpiresAtAsync(oldExpired.Id, DateTimeOffset.UtcNow.AddDays(-10));

        // Backdate the "old" sessions' created_at well before the cutoff.
        await SetCreatedAtAsync(oldRevoked.Id, DateTimeOffset.UtcNow.AddDays(-30));
        await SetCreatedAtAsync(oldExpired.Id, DateTimeOffset.UtcNow.AddDays(-30));

        var deleted = await _svc.CleanupAsync(DateTimeOffset.UtcNow.AddDays(-7));

        Assert.Equal(2, deleted);
        // Active and recently-revoked survive — verify directly.
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT id FROM user_sessions WHERE id = ANY(@ids)", conn);
        cmd.Parameters.AddWithValue("ids", new[] { oldRevoked.Id, oldExpired.Id, newRevoked.Id, active.Id });
        await using var reader = await cmd.ExecuteReaderAsync();
        var survivors = new HashSet<Guid>();
        while (await reader.ReadAsync()) survivors.Add(reader.GetGuid(0));

        Assert.Contains(active.Id, survivors);
        Assert.Contains(newRevoked.Id, survivors);
        Assert.DoesNotContain(oldRevoked.Id, survivors);
        Assert.DoesNotContain(oldExpired.Id, survivors);
    }

    [Fact]
    public async Task CleanupAsync_LeavesActiveSessionsAlone_RegardlessOfAge()
    {
        var (_, session) = await _svc.IssueAsync(_userId, null, null, BasicLifetime);
        await SetCreatedAtAsync(session.Id, DateTimeOffset.UtcNow.AddYears(-1));

        var deleted = await _svc.CleanupAsync(DateTimeOffset.UtcNow);

        Assert.Equal(0, deleted);
        var stored = await ReadSessionAsync(session.Id); // still there
        Assert.Equal(session.Id, stored.Id);
    }
}
