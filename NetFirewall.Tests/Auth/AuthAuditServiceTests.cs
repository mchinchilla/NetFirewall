using System.Net;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Auth;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Auth;

/// <summary>
/// Real-Postgres coverage for <see cref="AuthAuditService"/>. The service is a
/// thin INSERT + ORDER BY DESC reader, but it has subtle bits worth pinning:
/// JSONB serialization camelCase, optional FK to users (ON DELETE SET NULL),
/// and the DESC ordering the security UI relies on.
/// </summary>
[Collection("Postgres")]
public sealed class AuthAuditServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private AuthAuditService _svc = null!;

    public AuthAuditServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _svc = new AuthAuditService(_pg.DataSource);
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

    // ── basic write path ───────────────────────────────────────────────

    [Fact]
    public async Task LogAsync_PersistsAllFields()
    {
        var uid = await SeedUserAsync("alice");
        var ip = IPAddress.Parse("203.0.113.42");

        await _svc.LogAsync(
            AuthAuditEvents.LoginSuccess,
            userId: uid,
            username: "alice",
            ip: ip,
            userAgent: "Mozilla/5.0",
            detail: new { reason = "password+totp" });

        var entries = await _svc.RecentAsync();
        var entry = Assert.Single(entries);

        Assert.Equal(AuthAuditEvents.LoginSuccess, entry.EventType);
        Assert.Equal(uid, entry.UserId);
        Assert.Equal("alice", entry.Username);
        Assert.Equal(ip, entry.Ip);
        Assert.Equal("Mozilla/5.0", entry.UserAgent);
        // Detail is serialized via JsonNamingPolicy.CamelCase → "reason" stays lower.
        Assert.Contains("\"reason\": \"password+totp\"", entry.Detail);
        // Postgres assigns occurred_at via DEFAULT now(); should be very recent.
        Assert.True(entry.OccurredAt > DateTimeOffset.UtcNow.AddMinutes(-1));
        Assert.True(entry.Id > 0);
    }

    [Fact]
    public async Task LogAsync_DetailIsSerializedAsCamelCaseJson()
    {
        await _svc.LogAsync(
            AuthAuditEvents.TotpVerified,
            detail: new { StepCounter = 12345L, RemoteEndPoint = "10.0.0.1:54321" });

        var entry = (await _svc.RecentAsync()).Single();

        // C# property names PascalCase → JSON should emit camelCase.
        Assert.Contains("\"stepCounter\": 12345", entry.Detail);
        Assert.Contains("\"remoteEndPoint\": \"10.0.0.1:54321\"", entry.Detail);
    }

    [Fact]
    public async Task LogAsync_DetailNull_PersistsAsNullColumn()
    {
        await _svc.LogAsync(AuthAuditEvents.Logout);
        var entry = (await _svc.RecentAsync()).Single();
        Assert.Null(entry.Detail);
    }

    [Fact]
    public async Task LogAsync_AnonymousAttempt_NoUserIdOrUsername()
    {
        // login.failed for an unknown username — userId stays null.
        await _svc.LogAsync(
            AuthAuditEvents.LoginFailed,
            username: "ghost-user",
            ip: IPAddress.Parse("10.0.0.99"),
            detail: new { reason = "no such user" });

        var entry = (await _svc.RecentAsync()).Single();
        Assert.Null(entry.UserId);
        Assert.Equal("ghost-user", entry.Username);
    }

    // ── JSONB column ────────────────────────────────────────────────────

    [Fact]
    public async Task LogAsync_DetailIsActuallyJsonbInDatabase_NotText()
    {
        // Use a Postgres-side JSON operator to prove the column is jsonb,
        // not text — protects the schema contract.
        await _svc.LogAsync(AuthAuditEvents.TotpFailed, detail: new { CodeLength = 5 });

        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT detail->>'codeLength' FROM auth_audit_log LIMIT 1", conn);
        var v = (string?)await cmd.ExecuteScalarAsync();
        Assert.Equal("5", v);
    }

    // ── ordering & limit ───────────────────────────────────────────────

    [Fact]
    public async Task RecentAsync_OrdersByOccurredAtDesc()
    {
        await _svc.LogAsync("evt.alpha");
        await Task.Delay(20);
        await _svc.LogAsync("evt.bravo");
        await Task.Delay(20);
        await _svc.LogAsync("evt.charlie");

        var entries = await _svc.RecentAsync();

        Assert.Equal(new[] { "evt.charlie", "evt.bravo", "evt.alpha" },
            entries.Select(e => e.EventType));
    }

    [Fact]
    public async Task RecentAsync_LimitCapsResultCount()
    {
        for (var i = 0; i < 10; i++)
            await _svc.LogAsync($"evt.{i}");

        var capped = await _svc.RecentAsync(limit: 3);

        Assert.Equal(3, capped.Count);
    }

    // ── FK behavior ────────────────────────────────────────────────────

    [Fact]
    public async Task LogAsync_ThenUserDeleted_PreservesAuditRow_WithUserIdSetToNull()
    {
        // CLAUDE-doc'd contract: user_id REFERENCES users(id) ON DELETE SET NULL.
        // Append-only audit must NOT cascade-delete when an account is removed.
        var uid = await SeedUserAsync("bob");
        await _svc.LogAsync(AuthAuditEvents.LoginSuccess, userId: uid, username: "bob");

        await using (var conn = await _pg.DataSource.OpenConnectionAsync())
        await using (var del = new NpgsqlCommand("DELETE FROM users WHERE id = @id", conn))
        {
            del.Parameters.AddWithValue("id", uid);
            await del.ExecuteNonQueryAsync();
        }

        var entries = await _svc.RecentAsync();
        var entry = Assert.Single(entries);
        Assert.Null(entry.UserId);                    // FK was set to NULL
        Assert.Equal("bob", entry.Username);          // username was captured for forensics
        Assert.Equal(AuthAuditEvents.LoginSuccess, entry.EventType);
    }

    [Fact]
    public async Task RecentAsync_OnEmptyTable_ReturnsEmptyList()
    {
        var entries = await _svc.RecentAsync();
        Assert.Empty(entries);
    }
}
