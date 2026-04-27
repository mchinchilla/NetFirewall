using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Vpn;
using NetFirewall.Tests.Infra;
using Xunit;

namespace NetFirewall.Tests.Vpn;

/// <summary>Real-Postgres CRUD coverage for <see cref="WireGuardService"/>.</summary>
[Collection("Postgres")]
public sealed class WireGuardServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private WireGuardService _svc = null!;

    public WireGuardServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _svc = new WireGuardService(_pg.DataSource, NullLogger<WireGuardService>.Instance);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private static WgServer NewServer() => new()
    {
        Name = "wg0",
        PrivateKey = "PRIV_KEY",
        PublicKey = "PUB_KEY",
        ListenPort = 51820,
        AddressCidr = "10.10.0.1/24",
        Enabled = true
    };

    // ── Server: insert + upsert + read ─────────────────────────────────

    [Fact]
    public async Task SaveServerAsync_NewRow_AssignsIdAndPersists()
    {
        var saved = await _svc.SaveServerAsync(NewServer());

        Assert.NotEqual(Guid.Empty, saved.Id);
        var fetched = await _svc.GetServerAsync();
        Assert.NotNull(fetched);
        Assert.Equal(saved.Id, fetched!.Id);
        Assert.Equal("PRIV_KEY", fetched.PrivateKey);
    }

    [Fact]
    public async Task SaveServerAsync_ExistingId_UpsertsViaOnConflict()
    {
        var s = await _svc.SaveServerAsync(NewServer());
        s.ListenPort = 51900;
        s.PostUp = "iptables ...";

        var second = await _svc.SaveServerAsync(s);
        Assert.Equal(s.Id, second.Id);

        var fetched = await _svc.GetServerAsync();
        Assert.Equal(51900, fetched!.ListenPort);
        Assert.Equal("iptables ...", fetched.PostUp);
    }

    [Fact]
    public async Task GetServerAsync_NoRows_ReturnsNull()
    {
        Assert.Null(await _svc.GetServerAsync());
    }

    [Fact]
    public async Task DeleteServerAsync_RemovesRow_ReturnsTrue_FalseForUnknown()
    {
        var s = await _svc.SaveServerAsync(NewServer());
        Assert.True(await _svc.DeleteServerAsync(s.Id));
        Assert.Null(await _svc.GetServerAsync());

        Assert.False(await _svc.DeleteServerAsync(Guid.NewGuid()));
    }

    // ── Peers ──────────────────────────────────────────────────────────

    [Fact]
    public async Task CreatePeerAsync_PersistsRow_WithGeneratedId()
    {
        var server = await _svc.SaveServerAsync(NewServer());
        var peer = await _svc.CreatePeerAsync(new WgPeer
        {
            ServerId = server.Id,
            Name = "alice",
            PublicKey = "PUB_alice",
            AllowedIps = new[] { "10.10.0.2/32" },
            Enabled = true
        });

        Assert.NotEqual(Guid.Empty, peer.Id);
        var fetched = await _svc.GetPeerByIdAsync(peer.Id);
        Assert.NotNull(fetched);
        Assert.Equal(server.Id, fetched!.ServerId);
        Assert.Equal("alice", fetched.Name);
        Assert.Equal(new[] { "10.10.0.2/32" }, fetched.AllowedIps);
    }

    [Fact]
    public async Task GetPeersAsync_OrdersByName_ScopedToServer()
    {
        var s1 = await _svc.SaveServerAsync(NewServer());
        await _svc.CreatePeerAsync(new WgPeer
            { ServerId = s1.Id, Name = "zulu", PublicKey = "PUBKEY_zulu_8chars+", AllowedIps = new[] { "10.10.0.4/32" } });
        await _svc.CreatePeerAsync(new WgPeer
            { ServerId = s1.Id, Name = "alpha", PublicKey = "PUBKEY_alpha_8chars", AllowedIps = new[] { "10.10.0.5/32" } });

        var peers = await _svc.GetPeersAsync(s1.Id);
        Assert.Equal(new[] { "alpha", "zulu" }, peers.Select(p => p.Name));
    }

    [Fact]
    public async Task UpdatePeerAsync_PersistsChanges()
    {
        var server = await _svc.SaveServerAsync(NewServer());
        var p = await _svc.CreatePeerAsync(new WgPeer
            { ServerId = server.Id, Name = "alice", PublicKey = "PUBKEY_LONG_ENOUGH_FOR_LOG", AllowedIps = new[] { "10.10.0.2/32" } });

        p.Name = "alice-v2";
        p.AllowedIps = new[] { "10.10.0.2/32", "192.168.5.0/24" };
        p.PresharedKey = "PSK";

        await _svc.UpdatePeerAsync(p);

        var fetched = await _svc.GetPeerByIdAsync(p.Id);
        Assert.Equal("alice-v2", fetched!.Name);
        Assert.Equal(2, fetched.AllowedIps.Length);
        Assert.Equal("PSK", fetched.PresharedKey);
    }

    [Fact]
    public async Task DeletePeerAsync_RemovesRow()
    {
        var server = await _svc.SaveServerAsync(NewServer());
        var p = await _svc.CreatePeerAsync(new WgPeer
            { ServerId = server.Id, Name = "doomed", PublicKey = "PUBKEY_LONG_ENOUGH_FOR_LOG", AllowedIps = new[] { "10.10.0.2/32" } });

        Assert.True(await _svc.DeletePeerAsync(p.Id));
        Assert.Null(await _svc.GetPeerByIdAsync(p.Id));
    }

    [Fact]
    public async Task DeleteServerAsync_CascadesToPeers()
    {
        // Schema declares wg_peers.server_id REFERENCES wg_servers ON DELETE CASCADE.
        var server = await _svc.SaveServerAsync(NewServer());
        var p = await _svc.CreatePeerAsync(new WgPeer
            { ServerId = server.Id, Name = "p", PublicKey = "PUBKEY_LONG_ENOUGH_FOR_LOG", AllowedIps = new[] { "10.10.0.2/32" } });

        await _svc.DeleteServerAsync(server.Id);

        Assert.Null(await _svc.GetPeerByIdAsync(p.Id));
    }
}
