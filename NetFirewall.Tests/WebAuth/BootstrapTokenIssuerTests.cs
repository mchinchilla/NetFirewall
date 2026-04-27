using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Auth;
using NetFirewall.Tests.Infra;
using NetFirewall.Web.Auth.Bootstrap;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// Real-Postgres tests for the startup hosted service that decides whether to
/// issue the one-time bootstrap token. Driven entirely off the users table
/// row count, so we test both arms (empty → issue; populated → skip).
/// </summary>
[Collection("Postgres")]
public sealed class BootstrapTokenIssuerTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;

    public BootstrapTokenIssuerTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
    }

    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>
    /// Build a minimal DI scope with the real services the issuer resolves.
    /// </summary>
    private (BootstrapTokenIssuer issuer, IBootstrapTokenStore store) BuildScope()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(_pg.DataSource);
        services.AddScoped<IUserService>(sp =>
            new UserService(_pg.DataSource, NullLogger<UserService>.Instance));
        services.AddSingleton<IBootstrapTokenStore, BootstrapTokenStore>();

        var sp = services.BuildServiceProvider();
        var issuer = new BootstrapTokenIssuer(sp, NullLogger<BootstrapTokenIssuer>.Instance);
        // Resolve the singleton outside the scope so it survives across calls.
        var store = sp.GetRequiredService<IBootstrapTokenStore>();
        return (issuer, store);
    }

    [Fact]
    public async Task StartAsync_UsersTableEmpty_IssuesToken_AndStoreIsActive()
    {
        var (issuer, store) = BuildScope();
        Assert.False(store.IsActive); // pre-condition

        await issuer.StartAsync(CancellationToken.None);

        Assert.True(store.IsActive);
        Assert.NotNull(store.CurrentToken);
        Assert.True(store.CurrentToken!.Length > 20); // 24 random bytes → ~32 base64 chars
    }

    [Fact]
    public async Task StartAsync_UsersTableHasRow_DoesNotIssueToken()
    {
        // Seed one user to flip the count > 0 check.
        var users = new UserService(_pg.DataSource, NullLogger<UserService>.Instance);
        await users.CreateAsync(new User
        {
            Username = "preexisting",
            PasswordHash = "$argon2id$x",
            Role = UserRoles.Admin
        });

        var (issuer, store) = BuildScope();
        await issuer.StartAsync(CancellationToken.None);

        Assert.False(store.IsActive);
        Assert.Null(store.CurrentToken);
    }

    [Fact]
    public async Task StartAsync_UsersTableMissing_DoesNotThrow_StoreInactive()
    {
        // Wipe schema entirely so the count query fails — issuer must swallow
        // the exception (logged) and leave the store inactive.
        await _pg.ResetSchemaAsync();

        var (issuer, store) = BuildScope();
        await issuer.StartAsync(CancellationToken.None);

        Assert.False(store.IsActive);
    }

    [Fact]
    public async Task StartAsync_TokenIsUrlSafeBase64()
    {
        var (issuer, store) = BuildScope();
        await issuer.StartAsync(CancellationToken.None);

        // No '+', '/', or '=' — the issuer transforms to URL-safe form so it can
        // be pasted into the /setup/bootstrap?token=... query string verbatim.
        var t = store.CurrentToken!;
        Assert.DoesNotContain('+', t);
        Assert.DoesNotContain('/', t);
        Assert.DoesNotContain('=', t);
    }
}
