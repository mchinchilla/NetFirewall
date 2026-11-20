using NetFirewall.Models.Vpn;
using NetFirewall.Services.Vpn;
using Xunit;

namespace NetFirewall.Tests.Vpn;

/// <summary>
/// The one-interface-per-role redesign must not move a single byte of a LIVE legacy
/// interface: tekium's dual-role wg0 (listens for clients AND dials an upstream) has to
/// render exactly as before until the operator chooses to split it. Pinned against the
/// pre-redesign renderer output (only the timestamp line is volatile).
/// </summary>
public sealed class WireGuardConfigGoldenTests
{
    private static string Render(WgServer s, IReadOnlyList<WgPeer> peers) =>
        string.Join('\n', new WireGuardConfigService().GenerateServerConfig(s, peers)
            .Split('\n').Where(l => !l.StartsWith("# Generated:", StringComparison.Ordinal)));

    private static WgServer LegacyDualRole() => new()
    {
        Id = Guid.NewGuid(), Name = "wg0", Mode = "server",
        PrivateKey = "SRV_PRIV", PublicKey = "SRV_PUB",
        ListenPort = 51820, AddressCidr = "10.10.0.1/24",
        Dns = "1.1.1.1", Mtu = 1420, TableOff = true, Enabled = true,
    };

    private static IReadOnlyList<WgPeer> LegacyPeers() =>
    [
        new() { Name = "us-vpn", Role = "upstream", PublicKey = "UP_PUB", AllowedIps = ["0.0.0.0/0"],
                Endpoint = "vpn.example.net:51820", PersistentKeepalive = 25, Enabled = true },
        new() { Name = "laptop", Role = "client", PublicKey = "LP_PUB", PresharedKey = "PSK",
                AllowedIps = ["10.10.0.2/32"], Description = "road warrior", Enabled = true },
        new() { Name = "branch", Role = "site", RouteMode = "site", PublicKey = "BR_PUB",
                AllowedIps = ["10.10.0.3/32", "192.168.50.0/24"], AllowedSubnets = ["192.168.50.0/24"],
                Endpoint = "branch.example.net:51820", Enabled = true },
        new() { Name = "old", Role = "client", PublicKey = "OLD_PUB", AllowedIps = ["10.10.0.9/32"], Enabled = false },
    ];

    private const string Golden = """
        # NetFirewall WireGuard config

        [Interface]
        PrivateKey = SRV_PRIV
        Address    = 10.10.0.1/24
        ListenPort = 51820
        DNS        = 1.1.1.1
        MTU        = 1420
        Table      = off

        # us-vpn
        [Peer]
        PublicKey  = UP_PUB
        AllowedIPs = 0.0.0.0/0
        Endpoint   = vpn.example.net:51820
        PersistentKeepalive = 25

        # laptop — road warrior
        [Peer]
        PublicKey  = LP_PUB
        PresharedKey = PSK
        AllowedIPs = 10.10.0.2/32

        # branch
        [Peer]
        PublicKey  = BR_PUB
        AllowedIPs = 10.10.0.3/32, 192.168.50.0/24
        Endpoint   = branch.example.net:51820

        """;

    [Fact]
    public void LegacyDualRoleInterface_RendersByteIdentical()
    {
        var expected = Golden.ReplaceLineEndings("\n");
        var actual = Render(LegacyDualRole(), LegacyPeers()).ReplaceLineEndings("\n");
        Assert.Equal(expected, actual);
    }
}

public sealed class WireGuardConfigPerRoleTests
{
    private static string Render(WgServer s, params WgPeer[] peers) => new WireGuardConfigService().GenerateServerConfig(s, peers);

    [Fact]
    public void ClientKindInterface_AlwaysRendersTableOff_EvenWhenTheFlagIsClear()
    {
        var s = new WgServer { Name = "wgc1", Mode = "client", PrivateKey = "K", AddressCidr = "10.64.0.2/32", ListenPort = 0, TableOff = false };
        var conf = Render(s, new WgPeer { Name = "provider", Role = "upstream", PublicKey = "P", AllowedIps = ["0.0.0.0/0"], Enabled = true });
        Assert.Contains("Table      = off", conf);
        Assert.DoesNotContain("ListenPort", conf);
    }

    [Fact]
    public void SitePeer_RemoteSubnets_AreAddedToAllowedIps_Once()
    {
        var s = new WgServer { Name = "wg0", Mode = "server", PrivateKey = "K", AddressCidr = "10.10.0.1/24", ListenPort = 51820 };
        var conf = Render(s, new WgPeer
        {
            Name = "branch", Role = "site", RouteMode = "site", PublicKey = "B", Enabled = true,
            AllowedIps = ["10.10.0.3/32", "192.168.60.0/24"], AllowedSubnets = ["192.168.50.0/24", "192.168.60.0/24"],
        });
        Assert.Contains("AllowedIPs = 10.10.0.3/32, 192.168.60.0/24, 192.168.50.0/24", conf);
    }

    [Fact]
    public void ClientPeer_RestrictedSubnets_AreNotAllowedIps()
    {
        // 'restricted' subnets are what a road warrior may REACH on our LAN, not its own source range.
        var s = new WgServer { Name = "wg0", Mode = "server", PrivateKey = "K", AddressCidr = "10.10.0.1/24", ListenPort = 51820 };
        var conf = Render(s, new WgPeer
        {
            Name = "laptop", Role = "client", RouteMode = "restricted", PublicKey = "L", Enabled = true,
            AllowedIps = ["10.10.0.2/32"], AllowedSubnets = ["192.168.1.0/24"],
        });
        Assert.Contains("AllowedIPs = 10.10.0.2/32\n", conf.ReplaceLineEndings("\n"));
    }
}
