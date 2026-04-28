using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Auth;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Auth;

/// <summary>
/// Real-Postgres coverage for <see cref="UserService"/>. Includes the lockout
/// state machine — the only piece of UserService with non-trivial branching.
/// </summary>
[Collection("Postgres")]
public sealed class UserServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private UserService _svc = null!;

    public UserServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _svc = new UserService(_pg.DataSource, NullLogger<UserService>.Instance);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private static User MakeUser(string username = "alice", string role = UserRoles.Viewer) => new()
    {
        Username = username,
        Email = $"{username}@example.com",
        PasswordHash = "$argon2id$fake-but-non-empty",
        Role = role,
        IsActive = true
    };

    // ── Create + Get ───────────────────────────────────────────────────

    [Fact]
    public async Task CreateAsync_PersistsUser_WithGeneratedIdAndTimestamps()
    {
        var u = await _svc.CreateAsync(MakeUser());

        Assert.NotEqual(Guid.Empty, u.Id);
        Assert.NotEqual(default, u.CreatedAt);
        Assert.Equal(u.CreatedAt, u.UpdatedAt);

        var fetched = await _svc.GetByIdAsync(u.Id);
        Assert.NotNull(fetched);
        Assert.Equal("alice", fetched!.Username);
        Assert.Equal("alice@example.com", fetched.Email);
        Assert.Equal(UserRoles.Viewer, fetched.Role);
        Assert.True(fetched.IsActive);
        Assert.Equal(0, fetched.FailedLoginCount);
        Assert.Null(fetched.LockedUntil);
        Assert.Equal("UTC", fetched.Timezone); // default from migration
    }

    [Fact]
    public async Task CreateAsync_RespectsCallerProvidedId_WhenNotEmpty()
    {
        var u = MakeUser();
        var supplied = Guid.NewGuid();
        u.Id = supplied;

        var created = await _svc.CreateAsync(u);

        Assert.Equal(supplied, created.Id);
    }

    [Fact]
    public async Task CreateAsync_InvalidRole_Throws()
    {
        var u = MakeUser();
        u.Role = "godmode";
        await Assert.ThrowsAsync<ArgumentException>(() => _svc.CreateAsync(u));
    }

    [Fact]
    public async Task CreateAsync_DuplicateUsername_FailsAtDb()
    {
        await _svc.CreateAsync(MakeUser("dup"));
        await Assert.ThrowsAsync<PostgresException>(() => _svc.CreateAsync(MakeUser("dup")));
    }

    [Fact]
    public async Task GetByUsernameAsync_ReturnsExisting_AndNullForUnknown()
    {
        var u = await _svc.CreateAsync(MakeUser("known"));
        Assert.Equal(u.Id, (await _svc.GetByUsernameAsync("known"))?.Id);
        Assert.Null(await _svc.GetByUsernameAsync("missing"));
    }

    [Fact]
    public async Task ListAsync_OrdersByUsername_AndCountAsyncMatches()
    {
        await _svc.CreateAsync(MakeUser("zulu"));
        await _svc.CreateAsync(MakeUser("alpha"));
        await _svc.CreateAsync(MakeUser("mike"));

        var all = await _svc.ListAsync();
        Assert.Equal(new[] { "alpha", "mike", "zulu" }, all.Select(u => u.Username));
        Assert.Equal(3, await _svc.CountAsync());
    }

    // ── Mutations ──────────────────────────────────────────────────────

    [Fact]
    public async Task UpdatePasswordHashAsync_ReplacesHash_AndBumpsUpdatedAt()
    {
        var u = await _svc.CreateAsync(MakeUser());
        var originalUpdated = u.UpdatedAt;
        await Task.Delay(20);

        await _svc.UpdatePasswordHashAsync(u.Id, "$argon2id$new-hash");

        var fetched = await _svc.GetByIdAsync(u.Id);
        Assert.Equal("$argon2id$new-hash", fetched!.PasswordHash);
        Assert.True(fetched.UpdatedAt > originalUpdated);
    }

    [Fact]
    public async Task SetActiveAsync_TogglesIsActiveFlag()
    {
        var u = await _svc.CreateAsync(MakeUser());
        await _svc.SetActiveAsync(u.Id, false);
        Assert.False((await _svc.GetByIdAsync(u.Id))!.IsActive);

        await _svc.SetActiveAsync(u.Id, true);
        Assert.True((await _svc.GetByIdAsync(u.Id))!.IsActive);
    }

    [Fact]
    public async Task SetRoleAsync_ChangesRole()
    {
        var u = await _svc.CreateAsync(MakeUser(role: UserRoles.Viewer));
        await _svc.SetRoleAsync(u.Id, UserRoles.Operator);

        Assert.Equal(UserRoles.Operator, (await _svc.GetByIdAsync(u.Id))!.Role);
    }

    [Fact]
    public async Task SetRoleAsync_InvalidRole_Throws()
    {
        var u = await _svc.CreateAsync(MakeUser());
        await Assert.ThrowsAsync<ArgumentException>(() => _svc.SetRoleAsync(u.Id, "godmode"));

        // Original role unchanged.
        Assert.Equal(UserRoles.Viewer, (await _svc.GetByIdAsync(u.Id))!.Role);
    }

    // ── Lockout state machine ──────────────────────────────────────────

    [Fact]
    public async Task RecordLoginFailureAsync_UnderThreshold_IncrementsButDoesNotLock()
    {
        var u = await _svc.CreateAsync(MakeUser());

        var locked1 = await _svc.RecordLoginFailureAsync(u.Id, IPAddress.Loopback, threshold: 5, TimeSpan.FromMinutes(10));
        var locked2 = await _svc.RecordLoginFailureAsync(u.Id, IPAddress.Loopback, threshold: 5, TimeSpan.FromMinutes(10));

        Assert.False(locked1);
        Assert.False(locked2);

        var fetched = await _svc.GetByIdAsync(u.Id);
        Assert.Equal(2, fetched!.FailedLoginCount);
        Assert.Null(fetched.LockedUntil);
    }

    [Fact]
    public async Task RecordLoginFailureAsync_OnThresholdExceeded_LocksAccount()
    {
        var u = await _svc.CreateAsync(MakeUser());
        bool finalLocked = false;
        for (var i = 0; i < 5; i++)
            finalLocked = await _svc.RecordLoginFailureAsync(u.Id, IPAddress.Loopback, threshold: 5, TimeSpan.FromMinutes(10));

        Assert.True(finalLocked);

        var fetched = await _svc.GetByIdAsync(u.Id);
        Assert.Equal(5, fetched!.FailedLoginCount);
        Assert.NotNull(fetched.LockedUntil);
        var ttl = fetched.LockedUntil!.Value - DateTimeOffset.UtcNow;
        Assert.InRange(ttl.TotalMinutes, 9.5, 10.5);
    }

    [Fact]
    public async Task RecordLoginSuccessAsync_ClearsFailureCounter_AndStampsLastLogin()
    {
        var u = await _svc.CreateAsync(MakeUser());
        // Pile up 3 failures (under threshold).
        for (var i = 0; i < 3; i++)
            await _svc.RecordLoginFailureAsync(u.Id, IPAddress.Loopback, threshold: 5, TimeSpan.FromMinutes(10));

        var ip = IPAddress.Parse("203.0.113.7");
        await _svc.RecordLoginSuccessAsync(u.Id, ip);

        var fetched = await _svc.GetByIdAsync(u.Id);
        Assert.Equal(0, fetched!.FailedLoginCount);
        Assert.Null(fetched.LockedUntil);
        Assert.NotNull(fetched.LastLoginAt);
        Assert.Equal(ip, fetched.LastLoginIp);
    }

    [Fact]
    public async Task ClearLockoutAsync_ClearsCounterAndLock_WithoutTouchingLastLogin()
    {
        // The recovery path uses ClearLockoutAsync precisely BECAUSE it must
        // not stamp last_login_at — that would record a fake "successful login"
        // event and pollute the audit timeline. Pin both halves of the contract.
        var u = await _svc.CreateAsync(MakeUser());
        for (var i = 0; i < 5; i++)
            await _svc.RecordLoginFailureAsync(u.Id, IPAddress.Loopback, threshold: 5, TimeSpan.FromMinutes(10));

        var beforeFetched = await _svc.GetByIdAsync(u.Id);
        Assert.NotNull(beforeFetched!.LockedUntil);
        Assert.Null(beforeFetched.LastLoginAt); // no logins yet

        await _svc.ClearLockoutAsync(u.Id);

        var fetched = await _svc.GetByIdAsync(u.Id);
        Assert.Equal(0, fetched!.FailedLoginCount);
        Assert.Null(fetched.LockedUntil);
        // Critical: last_login_at MUST stay null. A regression that copy-pasted
        // RecordLoginSuccessAsync's SQL would set it to now() and this fails.
        Assert.Null(fetched.LastLoginAt);
        Assert.Null(fetched.LastLoginIp);
    }

    [Fact]
    public async Task ClearLockoutAsync_OnAlreadyClearUser_IsNoOp()
    {
        // Idempotent — recovery should be safe to re-run if the operator
        // double-clicked or restarted the flow.
        var u = await _svc.CreateAsync(MakeUser());

        await _svc.ClearLockoutAsync(u.Id);
        await _svc.ClearLockoutAsync(u.Id);

        var fetched = await _svc.GetByIdAsync(u.Id);
        Assert.Equal(0, fetched!.FailedLoginCount);
        Assert.Null(fetched.LockedUntil);
    }

    [Fact]
    public async Task RecordLoginSuccessAsync_ClearsLockoutEvenAfterPriorLock()
    {
        // Simulates the "lockout expired, user finally logs in successfully" path.
        var u = await _svc.CreateAsync(MakeUser());
        for (var i = 0; i < 5; i++)
            await _svc.RecordLoginFailureAsync(u.Id, IPAddress.Loopback, threshold: 5, TimeSpan.FromMinutes(10));
        Assert.NotNull((await _svc.GetByIdAsync(u.Id))!.LockedUntil);

        await _svc.RecordLoginSuccessAsync(u.Id, IPAddress.Loopback);

        var fetched = await _svc.GetByIdAsync(u.Id);
        Assert.Equal(0, fetched!.FailedLoginCount);
        Assert.Null(fetched.LockedUntil);
    }

    [Fact]
    public async Task RecordLoginFailureAsync_AfterLock_ExtendsLockoutOnEachAttempt()
    {
        // Sliding lock — every additional failed attempt while already locked
        // bumps locked_until forward. Defends against an attacker timing the
        // lockout to expire and then retrying instantly. The CASE in the SQL
        // fires on every attempt where (count+1) ≥ threshold, not just on
        // the boundary crossing.
        var u = await _svc.CreateAsync(MakeUser());
        for (var i = 0; i < 5; i++)
            await _svc.RecordLoginFailureAsync(u.Id, IPAddress.Loopback, threshold: 5, TimeSpan.FromMinutes(10));
        var firstLockedUntil = (await _svc.GetByIdAsync(u.Id))!.LockedUntil!.Value;

        await Task.Delay(50);
        await _svc.RecordLoginFailureAsync(u.Id, IPAddress.Loopback, threshold: 5, TimeSpan.FromMinutes(10));

        var fetched = await _svc.GetByIdAsync(u.Id);
        Assert.Equal(6, fetched!.FailedLoginCount);
        Assert.NotNull(fetched.LockedUntil);
        Assert.True(fetched.LockedUntil!.Value > firstLockedUntil,
            $"expected sliding lockout extension; first={firstLockedUntil:O}, after={fetched.LockedUntil:O}");
    }

    [Fact]
    public async Task RecordLoginFailureAsync_UnknownUser_ReturnsFalse()
    {
        Assert.False(await _svc.RecordLoginFailureAsync(
            Guid.NewGuid(), IPAddress.Loopback, threshold: 5, TimeSpan.FromMinutes(10)));
    }

    // ── Profile updates ────────────────────────────────────────────────

    [Fact]
    public async Task UpdateProfileAsync_PersistsAllFields_AndReturnsRefreshedUser()
    {
        var u = await _svc.CreateAsync(MakeUser());

        var updated = await _svc.UpdateProfileAsync(u.Id, new UserProfileUpdate(
            FirstName: "Alice", LastName: "Liddell", DisplayName: "Alice L.",
            Email: "alice.l@example.com", Phone: "+1-555-0100",
            Timezone: "America/New_York", Locale: "en-US"));

        Assert.Equal("Alice", updated.FirstName);
        Assert.Equal("Liddell", updated.LastName);
        Assert.Equal("Alice L.", updated.DisplayName);
        Assert.Equal("alice.l@example.com", updated.Email);
        Assert.Equal("+1-555-0100", updated.Phone);
        Assert.Equal("America/New_York", updated.Timezone);
        Assert.Equal("en-US", updated.Locale);
    }

    [Fact]
    public async Task UpdateProfileAsync_TrimsWhitespace_AndNullifiesEmptyStrings()
    {
        var u = await _svc.CreateAsync(MakeUser());

        var updated = await _svc.UpdateProfileAsync(u.Id, new UserProfileUpdate(
            FirstName: "  Alice  ", LastName: "", DisplayName: null,
            Email: "  ", Phone: " 555 ", Timezone: null, Locale: null));

        Assert.Equal("Alice", updated.FirstName);
        Assert.Null(updated.LastName);    // empty → null
        Assert.Null(updated.DisplayName);
        Assert.Null(updated.Email);       // whitespace → null
        Assert.Equal("555", updated.Phone);
    }

    [Fact]
    public async Task UpdateProfileAsync_NullTimezoneAndLocale_PreserveCurrentValues()
    {
        // COALESCE semantics: passing null doesn't wipe these fields.
        var u = await _svc.CreateAsync(MakeUser());
        await _svc.UpdateProfileAsync(u.Id, new UserProfileUpdate(
            FirstName: "Alice", LastName: null, DisplayName: null,
            Email: null, Phone: null,
            Timezone: "America/New_York", Locale: "en-US"));

        // Now update with timezone/locale=null — they should keep the prior values.
        var second = await _svc.UpdateProfileAsync(u.Id, new UserProfileUpdate(
            FirstName: "Alice", LastName: "L", DisplayName: null,
            Email: null, Phone: null,
            Timezone: null, Locale: null));

        Assert.Equal("America/New_York", second.Timezone);
        Assert.Equal("en-US", second.Locale);
    }

    [Fact]
    public async Task UpdateProfileAsync_UnknownUserId_Throws()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _svc.UpdateProfileAsync(Guid.NewGuid(),
                new UserProfileUpdate(null, null, null, null, null, null, null)));
    }
}
