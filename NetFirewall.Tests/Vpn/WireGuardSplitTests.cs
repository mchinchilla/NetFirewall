using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Daemon;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Vpn;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Vpn;

/// <summary>Splitting tekium's dual-role wg0: plan (pure) and execution (real Postgres, mocked daemon).</summary>
public sealed class WireGuardSplitPlannerTests
{
    private static readonly Guid Wg0Iface = Guid.NewGuid();

    private static WgServer Wg0() => new()
    {
        Id = Guid.NewGuid(), Name = "wg0", Mode = "client", ListenPort = 51820, TableOff = true,
        AddressCidr = "10.10.0.1/24, 192.168.3.2/32", PrivateKey = "K", PublicKey = "P",
    };

    private static List<WgPeer> Peers() =>
    [
        new() { Id = Guid.NewGuid(), Name = "us-vpn", Role = "upstream", Endpoint = "73.213.125.58:51821", AllowedIps = ["0.0.0.0/0"] },
        new() { Id = Guid.NewGuid(), Name = "laptop", Role = "client", AllowedIps = ["10.10.0.5/32"] },
        new() { Id = Guid.NewGuid(), Name = "phone", Role = "client", AllowedIps = ["10.10.0.6/32"] },
        new() { Id = Guid.NewGuid(), Name = "branch-in", Role = "site", AllowedIps = ["10.10.0.9/32"], AllowedSubnets = ["192.168.50.0/24"] },
    ];

    [Fact]
    public void Plan_KeepsWg0Outbound_MovesTheServerSideToWg1()
    {
        var hand = new FwNatRule { Id = Guid.NewGuid(), Type = "masquerade", SourceNetwork = "192.168.99.0/24", OutputInterfaceId = Wg0Iface, Description = "tekium egress" };
        var auto = new FwNatRule { Id = Guid.NewGuid(), Type = "masquerade", OutputInterfaceId = Wg0Iface, Description = "[vpn-auto] peer x → wan" };

        var plan = WireGuardSplitPlanner.Plan(Wg0(), Peers(), ["wg0"], Wg0Iface, [], [hand, auto]);

        Assert.True(plan.CanExecute, string.Join(" ", plan.Blockers));
        Assert.Equal("wg1", plan.ServerName);
        Assert.Equal(51820, plan.ListenPort);
        Assert.Equal(["10.10.0.1/24"], plan.AddressesToServer);           // holds the clients' addresses
        Assert.Equal(["192.168.3.2/32"], plan.AddressesKept);              // the provider-assigned one stays
        Assert.Equal(["laptop", "phone", "branch-in"], plan.PeersToServer.Select(p => p.Name));
        Assert.Equal(["us-vpn"], plan.PeersKept.Select(p => p.Name));
        Assert.Single(plan.HandRulesToReview);                             // the hand masquerade, not the [vpn-auto] row
    }

    [Fact]
    public void Plan_IsRefused_ForAnInterfaceThatDoesOneJob()
    {
        var outboundOnly = new WgServer { Name = "wgc1", Mode = "client", ListenPort = 0, AddressCidr = "10.64.0.2/32" };
        var plan = WireGuardSplitPlanner.Plan(outboundOnly, [Peers()[0]], ["wgc1"], null, [], []);
        Assert.False(plan.CanExecute);
    }

    [Fact]
    public void Plan_NeedsAnAddressOnEachSide()
    {
        var plan = WireGuardSplitPlanner.Plan(Wg0(), Peers(), ["wg0"], null, [], [], chosenServerAddresses: ["10.10.0.1/24", "192.168.3.2/32"]);
        Assert.False(plan.CanExecute);   // nothing left for the outbound tunnel
    }
}

[Collection("Postgres")]
public sealed class WireGuardSplitServiceTests(PostgresFixture pg) : IAsyncLifetime
{
    private WireGuardService _wg = null!;
    private readonly Mock<IDaemonClient> _daemon = new();
    private readonly Mock<IVpnRoutingService> _routing = new();
    private readonly Mock<IFirewallService> _fw = new();
    private readonly List<string> _calls = [];
    private WgServer _wg0 = null!;

    private static ServiceResponse<NftApplyResultDto> Ok() => ServiceResponse<NftApplyResultDto>.Ok(new NftApplyResultDto(0, null, "", null), "ok");

    public async Task InitializeAsync()
    {
        await pg.ResetSchemaAsync();
        await pg.BootstrapApplicationSchemaAsync();
        _wg = new WireGuardService(pg.DataSource, NullLogger<WireGuardService>.Instance);
        _wg0 = await _wg.SaveServerAsync(new WgServer
        {
            Name = "wg0", Mode = "client", ListenPort = 51820, TableOff = true, Enabled = true,
            AddressCidr = "10.10.0.1/24, 192.168.3.2/32", PrivateKey = "PRIV", PublicKey = "PUB",
        });
        await _wg.CreatePeerAsync(new WgPeer { ServerId = _wg0.Id, Name = "us-vpn", PublicKey = "UPSTREAMupstreamUPSTREAMupstreamUPSTREAMupst=", Role = "upstream", Endpoint = "1.2.3.4:51821", AllowedIps = ["0.0.0.0/0"], Enabled = true });
        await _wg.CreatePeerAsync(new WgPeer { ServerId = _wg0.Id, Name = "laptop", PublicKey = "LAPTOPlaptopLAPTOPlaptopLAPTOPlaptopLAPTOPla=", Role = "client", AllowedIps = ["10.10.0.5/32"], Enabled = true });

        _fw.Setup(f => f.GetFilterRulesAsync(It.IsAny<string?>(), It.IsAny<CancellationToken>())).ReturnsAsync([]);
        _fw.Setup(f => f.GetNatRulesAsync(It.IsAny<CancellationToken>())).ReturnsAsync([]);
        _daemon.Setup(d => d.ApplyWireGuardAsync(It.IsAny<string?>(), It.IsAny<CancellationToken>()))
               .Callback<string?, CancellationToken>((n, _) => _calls.Add($"apply {n}")).ReturnsAsync(Ok());
        _daemon.Setup(d => d.StopWireGuardAsync(It.IsAny<string?>(), It.IsAny<CancellationToken>()))
               .Callback<string?, CancellationToken>((n, _) => _calls.Add($"stop {n}")).ReturnsAsync(Ok());
        _daemon.Setup(d => d.ApplyFirewallAsync(It.IsAny<CancellationToken>()))
               .Callback(() => _calls.Add("firewall")).ReturnsAsync(Ok());
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private WireGuardSplitService Svc() => new(_wg, _routing.Object, _fw.Object, _daemon.Object, pg.DataSource, NullLogger<WireGuardSplitService>.Instance);

    [Fact]
    public async Task Execute_SplitsAndAppliesInTheOnlyWorkingOrder_ThenConfirm()
    {
        var r = await Svc().ExecuteAsync("wg0", ["10.10.0.1/24"], "admin");

        Assert.True(r.Success, r.Message);
        Assert.Equal(["apply wg0", "apply wg1", "firewall"], _calls);   // wg0 releases the port before wg1 binds it
        var wg0 = (await _wg.GetServerByNameAsync("wg0"))!;
        var wg1 = (await _wg.GetServerByNameAsync("wg1"))!;
        Assert.Equal((0, "192.168.3.2/32", "client"), (wg0.ListenPort, wg0.AddressCidr, wg0.Mode));
        Assert.Equal((51820, "10.10.0.1/24", "PRIV", "PUB"), (wg1.ListenPort, wg1.AddressCidr, wg1.PrivateKey, wg1.PublicKey));
        Assert.Equal(["laptop"], (await _wg.GetPeersAsync(wg1.Id)).Select(p => p.Name));
        Assert.Equal(["us-vpn"], (await _wg.GetPeersAsync(wg0.Id)).Select(p => p.Name));
        Assert.NotNull(await Svc().PendingAsync());

        Assert.True((await Svc().ConfirmAsync(r.Data!.Id)).Success);
        Assert.Null(await Svc().PendingAsync());
    }

    [Fact]
    public async Task Execute_WhenAnApplyFails_RevertsToTheOriginalWg0()
    {
        _daemon.Setup(d => d.ApplyWireGuardAsync("wg1", It.IsAny<CancellationToken>()))
               .ReturnsAsync(ServiceResponse<NftApplyResultDto>.Fail("bind: address in use"));

        var r = await Svc().ExecuteAsync("wg0", ["10.10.0.1/24"], "admin");

        Assert.False(r.Success);
        Assert.Contains("reverted", r.Message);
        var wg0 = (await _wg.GetServerByNameAsync("wg0"))!;
        Assert.Equal((51820, "10.10.0.1/24, 192.168.3.2/32", "client"), (wg0.ListenPort, wg0.AddressCidr, wg0.Mode));
        Assert.Equal(2, (await _wg.GetPeersAsync(wg0.Id)).Count);
        Assert.Null(await _wg.GetServerByNameAsync("wg1"));
        Assert.Null(await Svc().PendingAsync());
    }

    [Fact]
    public async Task Revert_StopsTheNewServerFirst_AndRestoresEverything()
    {
        var r = await Svc().ExecuteAsync("wg0", ["10.10.0.1/24"], "admin");
        _calls.Clear();

        var back = await Svc().RevertAsync(r.Data!.Id, "test");

        Assert.True(back.Success, back.Message);
        Assert.Equal(["stop wg1", "apply wg0", "firewall"], _calls);
        Assert.Equal(51820, (await _wg.GetServerByNameAsync("wg0"))!.ListenPort);
        Assert.Null(await _wg.GetServerByNameAsync("wg1"));
    }

    [Fact]
    public async Task OnlyOneSplitAtATime()
    {
        Assert.True((await Svc().ExecuteAsync("wg0", ["10.10.0.1/24"], "admin")).Success);
        var again = await Svc().ExecuteAsync("wg0", ["10.10.0.1/24"], "admin");
        Assert.False(again.Success);
    }
}
