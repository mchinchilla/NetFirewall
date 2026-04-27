using NetFirewall.Models.Vpn;
using NetFirewall.Services.Vpn;
using Xunit;

namespace NetFirewall.Tests.Vpn;

/// <summary>
/// Pure-function coverage of <see cref="WireGuardConfigService"/>. The output is
/// what wg-quick parses, so the layout matters: section headers, key=value lines,
/// and the order in which Peer blocks are emitted.
/// </summary>
public class WireGuardConfigServiceTests
{
    private readonly WireGuardConfigService _svc = new();

    private static WgServer Server() => new()
    {
        Id = Guid.NewGuid(),
        Name = "wg0",
        PrivateKey = "SERVER_PRIV_KEY",
        PublicKey = "SERVER_PUB_KEY",
        ListenPort = 51820,
        AddressCidr = "10.10.0.1/24",
        Enabled = true
    };

    private static WgPeer Peer(string name = "alice", bool enabled = true) => new()
    {
        Id = Guid.NewGuid(),
        Name = name,
        PublicKey = $"PUB_{name}",
        AllowedIps = new[] { "10.10.0.2/32" },
        Enabled = enabled
    };

    // ── Server config ──────────────────────────────────────────────────

    [Fact]
    public void ServerConfig_HasInterfaceBlockWithRequiredFields()
    {
        var cfg = _svc.GenerateServerConfig(Server(), Array.Empty<WgPeer>());

        Assert.Contains("[Interface]", cfg);
        Assert.Contains("PrivateKey = SERVER_PRIV_KEY", cfg);
        Assert.Contains("Address    = 10.10.0.1/24", cfg);
        Assert.Contains("ListenPort = 51820", cfg);
    }

    [Fact]
    public void ServerConfig_NoPostUpDown_OmitsLines()
    {
        var s = Server();
        s.PostUp = null;
        s.PostDown = null;
        var cfg = _svc.GenerateServerConfig(s, Array.Empty<WgPeer>());

        Assert.DoesNotContain("PostUp", cfg);
        Assert.DoesNotContain("PostDown", cfg);
    }

    [Fact]
    public void ServerConfig_WithPostUpDown_RendersBoth()
    {
        var s = Server();
        s.PostUp   = "iptables -A FORWARD -i %i -j ACCEPT";
        s.PostDown = "iptables -D FORWARD -i %i -j ACCEPT";
        var cfg = _svc.GenerateServerConfig(s, Array.Empty<WgPeer>());

        Assert.Contains("PostUp     = iptables -A FORWARD", cfg);
        Assert.Contains("PostDown   = iptables -D FORWARD", cfg);
    }

    [Fact]
    public void ServerConfig_EachEnabledPeer_RendersOnePeerBlock()
    {
        var peers = new[] { Peer("alice"), Peer("bob") };
        var cfg = _svc.GenerateServerConfig(Server(), peers);

        // Two [Peer] sections.
        Assert.Equal(2, cfg.Split("[Peer]").Length - 1);
        Assert.Contains("# alice", cfg);
        Assert.Contains("# bob", cfg);
        Assert.Contains("PublicKey  = PUB_alice", cfg);
        Assert.Contains("PublicKey  = PUB_bob", cfg);
    }

    [Fact]
    public void ServerConfig_DisabledPeer_IsOmitted()
    {
        var peers = new[] { Peer("alice"), Peer("bob", enabled: false) };
        var cfg = _svc.GenerateServerConfig(Server(), peers);

        Assert.Contains("# alice", cfg);
        Assert.DoesNotContain("# bob", cfg);
        Assert.Equal(1, cfg.Split("[Peer]").Length - 1);
    }

    [Fact]
    public void ServerConfig_PresharedKeyAndKeepalive_RenderedWhenSet()
    {
        var p = Peer();
        p.PresharedKey = "PSK_BYTES";
        p.PersistentKeepalive = 25;
        var cfg = _svc.GenerateServerConfig(Server(), new[] { p });

        Assert.Contains("PresharedKey = PSK_BYTES", cfg);
        Assert.Contains("PersistentKeepalive = 25", cfg);
    }

    [Fact]
    public void ServerConfig_KeepaliveZeroOrNull_NotRendered()
    {
        var p1 = Peer("a");
        p1.PersistentKeepalive = null;
        var p2 = Peer("b");
        p2.PersistentKeepalive = 0;
        var cfg = _svc.GenerateServerConfig(Server(), new[] { p1, p2 });

        Assert.DoesNotContain("PersistentKeepalive", cfg);
    }

    [Fact]
    public void ServerConfig_AllowedIps_JoinedWithCommaSpace()
    {
        var p = Peer();
        p.AllowedIps = new[] { "10.10.0.2/32", "192.168.5.0/24" };
        var cfg = _svc.GenerateServerConfig(Server(), new[] { p });

        Assert.Contains("AllowedIPs = 10.10.0.2/32, 192.168.5.0/24", cfg);
    }

    // ── Client config ──────────────────────────────────────────────────

    [Fact]
    public void ClientConfig_RendersInterfaceWithPrivateKeyAndAddress()
    {
        var cfg = _svc.GenerateClientConfig(
            Server(), Peer("alice"),
            clientPrivateKey: "CLIENT_PRIV",
            endpoint: "vpn.example.com",
            clientAddressCidr: "10.10.0.5/32",
            clientAllowedIps: new[] { "0.0.0.0/0" });

        Assert.Contains("[Interface]", cfg);
        Assert.Contains("PrivateKey = CLIENT_PRIV", cfg);
        Assert.Contains("Address    = 10.10.0.5/32", cfg);
    }

    [Fact]
    public void ClientConfig_PeerBlockUsesServerPublicKey_AndEndpointWithPort()
    {
        var cfg = _svc.GenerateClientConfig(
            Server(), Peer("alice"),
            clientPrivateKey: "CLIENT_PRIV",
            endpoint: "vpn.example.com",
            clientAddressCidr: "10.10.0.5/32",
            clientAllowedIps: new[] { "0.0.0.0/0" });

        Assert.Contains("[Peer]", cfg);
        Assert.Contains("PublicKey  = SERVER_PUB_KEY", cfg);
        Assert.Contains("Endpoint   = vpn.example.com:51820", cfg);
        Assert.Contains("AllowedIPs = 0.0.0.0/0", cfg);
    }

    [Fact]
    public void ClientConfig_DnsOmittedWhenNullOrWhitespace()
    {
        var cfgNull = _svc.GenerateClientConfig(
            Server(), Peer(), "x", "vpn.example.com", "10.10.0.5/32",
            new[] { "0.0.0.0/0" }, clientDns: null);
        Assert.DoesNotContain("DNS", cfgNull);

        var cfgWs = _svc.GenerateClientConfig(
            Server(), Peer(), "x", "vpn.example.com", "10.10.0.5/32",
            new[] { "0.0.0.0/0" }, clientDns: "   ");
        Assert.DoesNotContain("DNS", cfgWs);
    }

    [Fact]
    public void ClientConfig_DnsRenderedWhenSet()
    {
        var cfg = _svc.GenerateClientConfig(
            Server(), Peer(), "x", "vpn.example.com", "10.10.0.5/32",
            new[] { "0.0.0.0/0" }, clientDns: "1.1.1.1");
        Assert.Contains("DNS        = 1.1.1.1", cfg);
    }

    [Fact]
    public void ClientConfig_PresharedKey_OnlyEmittedWhenPeerHasOne()
    {
        var p = Peer();
        p.PresharedKey = "PSK_HERE";
        var cfg = _svc.GenerateClientConfig(
            Server(), p, "x", "vpn.example.com", "10.10.0.5/32",
            new[] { "0.0.0.0/0" });
        Assert.Contains("PresharedKey = PSK_HERE", cfg);

        var pNoPsk = Peer();
        pNoPsk.PresharedKey = null;
        var cfg2 = _svc.GenerateClientConfig(
            Server(), pNoPsk, "x", "vpn.example.com", "10.10.0.5/32",
            new[] { "0.0.0.0/0" });
        Assert.DoesNotContain("PresharedKey", cfg2);
    }
}
