using NetFirewall.Models.Vpn;
using NetFirewall.Web.Models.Vpn;
using Xunit;

namespace NetFirewall.Tests.Vpn;

/// <summary>An interface's role comes from what it does, not from wg_servers.mode (legacy until the redesign).</summary>
public sealed class WgInterfaceRoleTests
{
    private static WgPeer Peer(string role, string? endpoint = null) => new() { Id = Guid.NewGuid(), Role = role, Endpoint = endpoint, Enabled = true };

    [Theory]
    [InlineData("server", 51820, new string[0], WgRole.Server)]
    [InlineData("client", 0, new[] { "upstream" }, WgRole.Outbound)]
    [InlineData("client", 51820, new[] { "upstream", "client" }, WgRole.DualRole)]   // legacy wg0 that says 'client' but serves
    [InlineData("server", 51820, new[] { "upstream" }, WgRole.DualRole)]
    [InlineData("client", 0, new[] { "client" }, WgRole.Server)]                     // has road warriors: it serves
    [InlineData("client", 0, new string[0], WgRole.Outbound)]
    public void Classify(string mode, int port, string[] roles, WgRole expected) =>
        Assert.Equal(expected, WgInterfaceRole.Classify(
            new WgServer { Mode = mode, ListenPort = port },
            roles.Select(r => Peer(r, r == "upstream" ? "vpn.example:51820" : null)).ToList()));

    [Fact]
    public void ASiteThatDialsIsOutbound_ASiteThatDialsInIsServer()
    {
        Assert.Equal(WgRole.Outbound, WgInterfaceRole.Classify(new WgServer { ListenPort = 0 }, [Peer("site", "branch.example:51820")]));
        Assert.Equal(WgRole.Server, WgInterfaceRole.Classify(new WgServer { ListenPort = 0 }, [Peer("site")]));
    }

    [Theory]
    [InlineData(new[] { "wgc1" }, "wg0")]
    [InlineData(new[] { "wg0", "wgc1" }, "wg1")]   // wg0 taken by an outbound connection
    public void NextServerName(string[] taken, string expected) => Assert.Equal(expected, WgInterfaceRole.NextServerName(taken));

    [Fact]
    public void OutboundPage_ShowsALegacyClientModeWg0ThatServes_AsShared_NotAsACard()
    {
        var legacy = new WgServer { Id = Guid.NewGuid(), Name = "wg0", Mode = "client", ListenPort = 51820 };
        var provider = new WgServer { Id = Guid.NewGuid(), Name = "wgc1", Mode = "client", ListenPort = 0 };
        var vm = OutboundConnectionsPageViewModel.From(
        [
            (legacy, [Peer("upstream", "a:1"), Peer("client")]),
            (provider, [Peer("upstream", "b:1")]),
        ], null, null, false);

        Assert.Equal("wgc1", Assert.Single(vm.Connections).Interface.Name);
        Assert.Equal("wg0", vm.Shared!.Interface.Name);
        Assert.Single(vm.Shared.Tunnels);
    }
}
