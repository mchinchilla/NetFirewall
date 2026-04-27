using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Models.Network;
using NetFirewall.Services.Network;
using NetFirewall.Tests.Infra;
using Xunit;

namespace NetFirewall.Tests.Network;

/// <summary>
/// Real-Postgres CRUD for <see cref="NetworkServiceService"/>. Migration 20
/// seeds ~72 builtin services on schema bootstrap; tests use a unique prefix
/// (TestSvc-) so they don't collide with the catalog.
/// </summary>
[Collection("Postgres")]
public sealed class NetworkServiceServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private NetworkServiceService _svc = null!;
    private readonly string _prefix = $"TestSvc-{Guid.NewGuid().ToString("N")[..6]}-";

    public NetworkServiceServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _svc = new NetworkServiceService(_pg.DataSource, NullLogger<NetworkServiceService>.Instance);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private string N(string suffix) => _prefix + suffix;

    // ── CRUD ───────────────────────────────────────────────────────────

    [Fact]
    public async Task CreateAsync_PersistsRow_AndPortStringRendersCorrectly()
    {
        var created = await _svc.CreateAsync(new NetworkService
        {
            Name = N("ssh"),
            Protocol = NetworkServiceProtocols.Tcp,
            PortStart = 22,
            Description = "SSH",
            Category = "Remote"
        });

        var fetched = await _svc.GetByIdAsync(created.Id);
        Assert.NotNull(fetched);
        Assert.Equal(22, fetched!.PortStart);
        Assert.Null(fetched.PortEnd);
        Assert.Equal("22", fetched.PortString);
        Assert.False(fetched.IsBuiltin); // user-created, not seeded
    }

    [Fact]
    public async Task CreateAsync_RangePort_PortStringRendersHyphenated()
    {
        var created = await _svc.CreateAsync(new NetworkService
        {
            Name = N("rtp"),
            Protocol = NetworkServiceProtocols.Udp,
            PortStart = 10000,
            PortEnd = 20000,
            Category = "VoIP"
        });

        var fetched = await _svc.GetByIdAsync(created.Id);
        Assert.Equal("10000-20000", fetched!.PortString);
    }

    [Fact]
    public async Task GetByNameAsync_FindsBuiltin_AndCustom()
    {
        // Builtin: SSH should be in the seeded catalog.
        var ssh = await _svc.GetByNameAsync("SSH");
        Assert.NotNull(ssh);
        Assert.True(ssh!.IsBuiltin);

        // Custom one we add ourselves.
        await _svc.CreateAsync(new NetworkService
        {
            Name = N("custom"), Protocol = "tcp", PortStart = 12345
        });
        var mine = await _svc.GetByNameAsync(N("custom"));
        Assert.NotNull(mine);
        Assert.False(mine!.IsBuiltin);
    }

    [Fact]
    public async Task UpdateAsync_ChangesPortRange()
    {
        var c = await _svc.CreateAsync(new NetworkService
        {
            Name = N("svc"), Protocol = "tcp", PortStart = 100
        });

        c.PortStart = 200;
        c.PortEnd = 250;
        await _svc.UpdateAsync(c);

        var fetched = await _svc.GetByIdAsync(c.Id);
        Assert.Equal(200, fetched!.PortStart);
        Assert.Equal(250, fetched.PortEnd);
    }

    [Fact]
    public async Task DeleteAsync_RemovesRow()
    {
        var c = await _svc.CreateAsync(new NetworkService
        {
            Name = N("doomed"), Protocol = "tcp", PortStart = 999
        });
        Assert.True(await _svc.DeleteAsync(c.Id));
        Assert.Null(await _svc.GetByIdAsync(c.Id));
    }

    // ── Validation ─────────────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task CreateAsync_EmptyName_Throws(string name)
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            _svc.CreateAsync(new NetworkService { Name = name, Protocol = "tcp", PortStart = 80 }));
    }

    [Fact]
    public async Task CreateAsync_InvalidProtocol_Throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            _svc.CreateAsync(new NetworkService
            {
                Name = N("badproto"), Protocol = "raw", PortStart = 80
            }));
    }

    // ── Group membership ───────────────────────────────────────────────

    [Fact]
    public async Task SetGroupMembersAsync_StoresAndExposes_ViaIncludeMembers()
    {
        var http  = await _svc.CreateAsync(new NetworkService { Name = N("http"),  Protocol = "tcp", PortStart = 80 });
        var https = await _svc.CreateAsync(new NetworkService { Name = N("https"), Protocol = "tcp", PortStart = 443 });
        var grp   = await _svc.CreateAsync(new NetworkService
        {
            Name = N("web"), Protocol = "tcp", PortStart = 0  // group, port unused
        });

        await _svc.SetGroupMembersAsync(grp.Id, new[] { http.Id, https.Id });

        var loaded = await _svc.GetByIdAsync(grp.Id, includeMembers: true);
        Assert.NotNull(loaded?.Members);
        Assert.Equal(2, loaded!.Members!.Count);
    }

    [Fact]
    public async Task SetGroupMembersAsync_DropsParentSelfReference()
    {
        var grp  = await _svc.CreateAsync(new NetworkService { Name = N("g"), Protocol = "tcp", PortStart = 0 });
        var leaf = await _svc.CreateAsync(new NetworkService { Name = N("leaf"), Protocol = "tcp", PortStart = 80 });

        await _svc.SetGroupMembersAsync(grp.Id, new[] { grp.Id, leaf.Id });

        var loaded = await _svc.GetByIdAsync(grp.Id, includeMembers: true);
        Assert.Single(loaded!.Members!);
    }
}
