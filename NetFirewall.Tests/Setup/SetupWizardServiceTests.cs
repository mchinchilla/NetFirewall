using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Setup;
using NetFirewall.Models.System;
using NetFirewall.Services.Daemon;
using NetFirewall.Services.Dhcp;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Services.Setup;
using NetFirewall.Services.Vpn;
using NetFirewall.Tests.Infra;
using Xunit;

namespace NetFirewall.Tests.Setup;

/// <summary>
/// Real-Postgres coverage for <see cref="SetupWizardService"/> — the state
/// machine and JSON column persistence. Apply* methods (which mutate fw_* and
/// dhcp_* tables) are integration territory and are not exercised here.
/// </summary>
[Collection("Postgres")]
public sealed class SetupWizardServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private readonly Mock<IFirewallService> _firewall = new();
    private readonly Mock<IDhcpSubnetService> _subnets = new();
    private readonly Mock<ILinuxDistroService> _distro = new();
    private readonly Mock<IDaemonClient> _daemon = new();
    private readonly Mock<IWireGuardService> _wireguard = new();
    private SetupWizardService _svc = null!;

    public SetupWizardServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _distro.Setup(d => d.DiscoverInterfacesAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync(Array.Empty<InterfaceSuggestion>());
        _svc = new SetupWizardService(
            _pg.DataSource, _firewall.Object, _subnets.Object, _distro.Object,
            _daemon.Object, _wireguard.Object,
            NullLogger<SetupWizardService>.Instance);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    // ── State lifecycle ────────────────────────────────────────────────

    [Fact]
    public async Task IsWizardCompleted_FreshDb_ReturnsFalse()
    {
        Assert.False(await _svc.IsWizardCompletedAsync());
    }

    [Fact]
    public async Task GetOrCreate_OnFreshDb_CreatesSingletonRow_AtStep1()
    {
        var state1 = await _svc.GetOrCreateWizardStateAsync();
        Assert.NotEqual(Guid.Empty, state1.Id);
        Assert.Equal(1, state1.CurrentStep);
        Assert.False(state1.IsCompleted);

        // Subsequent calls return the SAME row, not a new one.
        var state2 = await _svc.GetOrCreateWizardStateAsync();
        Assert.Equal(state1.Id, state2.Id);
    }

    [Fact]
    public async Task CompleteWizard_FlipsIsCompletedAndSetsCompletedAt()
    {
        await _svc.GetOrCreateWizardStateAsync();
        Assert.False(await _svc.IsWizardCompletedAsync());

        await _svc.CompleteWizardAsync();

        Assert.True(await _svc.IsWizardCompletedAsync());
        var s = await _svc.GetOrCreateWizardStateAsync();
        Assert.True(s.IsCompleted);
        Assert.NotNull(s.CompletedAt);
    }

    // ── Interface discovery: prefer daemon (live IP/mask/gw), fall back to distro ──

    [Fact]
    public async Task DetectInterfaces_UsesDaemon_AndCarriesCurrentIpMaskGateway()
    {
        // The daemon (root, full PATH) reports the live config — including IP, mask,
        // and gateway. The Web's in-process `ip` calls can't (sandbox/PATH), so the
        // service must take the daemon's data and surface it to the form.
        _daemon.Setup(d => d.DiscoverInterfacesAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync(NetFirewall.Models.ServiceResponse<IReadOnlyList<InterfaceSuggestion>>.Ok(
                   new List<InterfaceSuggestion>
                   {
                       new()
                       {
                           Name = "ens192", SuggestedType = "WAN", SuggestedRole = "primary_wan",
                           MacAddress = "00:11:22:33:44:55", IsUp = true, Mtu = 1500,
                           CurrentIp = System.Net.IPAddress.Parse("203.0.113.10"),
                           CurrentSubnet = "203.0.113.10/24",
                           CurrentGateway = System.Net.IPAddress.Parse("203.0.113.1"),
                       }
                   }));

        var detected = await _svc.DetectNetworkInterfacesAsync();

        var nic = Assert.Single(detected);
        Assert.Equal("ens192", nic.Name);
        Assert.Equal("203.0.113.10", nic.CurrentIpAddress);
        Assert.Equal("255.255.255.0", nic.CurrentSubnetMask);   // CIDR /24 → dotted
        Assert.Equal("203.0.113.1", nic.CurrentGateway);
        Assert.Equal(1500, nic.Mtu);
        // Must NOT have fallen through to the (empty) local distro mock.
        _distro.Verify(d => d.DiscoverInterfacesAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task DetectInterfaces_ExcludesServiceManagedVirtualInterfaces()
    {
        // wg0/tun0/docker0/veth* are owned by services (WireGuard, OpenVPN, Docker),
        // not the NIC config layer — Step 1 must not offer them (else orphan config).
        _daemon.Setup(d => d.DiscoverInterfacesAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync(NetFirewall.Models.ServiceResponse<IReadOnlyList<InterfaceSuggestion>>.Ok(
                   new List<InterfaceSuggestion>
                   {
                       new() { Name = "ens192", SuggestedType = "WAN", SuggestedRole = "primary_wan", IsUp = true },
                       new() { Name = "ens256", SuggestedType = "LAN", SuggestedRole = "local_network", IsUp = true },
                       new() { Name = "wg0",     SuggestedType = "VPN", SuggestedRole = "vpn", IsVirtual = true, IsUp = true },
                       new() { Name = "tun0",    SuggestedType = "VPN", SuggestedRole = "vpn", IsVirtual = true },
                       new() { Name = "docker0", SuggestedType = "LAN", SuggestedRole = "local_network", IsVirtual = true },
                       new() { Name = "veth1a2b",SuggestedType = "LAN", SuggestedRole = "local_network", IsVirtual = true },
                   }));

        var detected = await _svc.DetectNetworkInterfacesAsync();

        var names = detected.Select(d => d.Name).ToList();
        Assert.Equal(new[] { "ens192", "ens256" }, names.OrderBy(n => n));
        Assert.DoesNotContain("wg0", names);
        Assert.DoesNotContain("tun0", names);
        Assert.DoesNotContain("docker0", names);
        Assert.DoesNotContain("veth1a2b", names);
    }

    [Fact]
    public async Task DetectInterfaces_DaemonDown_FallsBackToLocalDistro()
    {
        _daemon.Setup(d => d.DiscoverInterfacesAsync(It.IsAny<CancellationToken>()))
               .ThrowsAsync(new InvalidOperationException("daemon socket unavailable"));
        _distro.Setup(d => d.DiscoverInterfacesAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync(new List<InterfaceSuggestion>
               {
                   new() { Name = "eth0", SuggestedType = "LAN", SuggestedRole = "local_network",
                           CurrentIp = System.Net.IPAddress.Parse("192.168.1.1"), CurrentSubnet = "192.168.1.1/24" }
               });

        var detected = await _svc.DetectNetworkInterfacesAsync();

        var nic = Assert.Single(detected);
        Assert.Equal("eth0", nic.Name);
        Assert.Equal("192.168.1.1", nic.CurrentIpAddress);
        _distro.Verify(d => d.DiscoverInterfacesAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ResetWizard_ClearsAllStateAndStartsFresh()
    {
        await _svc.SaveStep1InterfacesAsync(new List<WizardInterfaceConfig>
        {
            new() { Name = "eth0", Role = "lan", IpAddress = "10.0.0.1" }
        });
        await _svc.CompleteWizardAsync();
        Assert.True(await _svc.IsWizardCompletedAsync());

        await _svc.ResetWizardAsync();

        Assert.False(await _svc.IsWizardCompletedAsync());
        var fresh = await _svc.GetOrCreateWizardStateAsync();
        Assert.Equal(1, fresh.CurrentStep);
        Assert.Null(fresh.InterfacesConfigJson);
    }

    // ── Step accessors round-trip ──────────────────────────────────────

    [Fact]
    public async Task SaveAndGetStep1_RoundTrip()
    {
        var input = new List<WizardInterfaceConfig>
        {
            new() { Name = "eth0", Role = "wan_primary", AddressingMode = "dhcp" },
            new() { Name = "eth1", Role = "lan", AddressingMode = "static", IpAddress = "10.0.0.1", SubnetMask = "255.255.255.0" }
        };

        await _svc.SaveStep1InterfacesAsync(input);

        var fetched = await _svc.GetStep1InterfacesAsync();
        Assert.NotNull(fetched);
        Assert.Equal(2, fetched!.Count);
        Assert.Equal("eth0", fetched[0].Name);
        Assert.Equal("wan_primary", fetched[0].Role);
        Assert.Equal("dhcp", fetched[0].AddressingMode);
        Assert.Equal("eth1", fetched[1].Name);
        Assert.Equal("static", fetched[1].AddressingMode);
        Assert.Equal("10.0.0.1", fetched[1].IpAddress);
    }

    [Fact]
    public async Task SaveAndGetStep2_RoundTrip()
    {
        var input = new List<WizardLanConfig>
        {
            new()
            {
                InterfaceName = "eth1",
                ServerIp = "10.0.0.1",
                NetworkCidr = "10.0.0.0/24",
                EnableDhcp = true,
                DhcpRangeStart = "10.0.0.100"
            }
        };

        await _svc.SaveStep2LanAsync(input);
        var fetched = await _svc.GetStep2LanAsync();

        Assert.NotNull(fetched);
        var single = Assert.Single(fetched!);
        Assert.Equal("eth1", single.InterfaceName);
        Assert.Equal("10.0.0.0/24", single.NetworkCidr);
    }

    [Fact]
    public async Task SaveAndGetStep3_RoundTrip()
    {
        var cfg = new WizardFirewallConfig();
        await _svc.SaveStep3FirewallAsync(cfg);

        var fetched = await _svc.GetStep3FirewallAsync();
        Assert.NotNull(fetched);
    }

    [Fact]
    public async Task SaveAndGetStep4_RoundTrip()
    {
        var cfg = new WizardServicesConfig();
        await _svc.SaveStep4ServicesAsync(cfg);

        var fetched = await _svc.GetStep4ServicesAsync();
        Assert.NotNull(fetched);
    }

    // ── Steps return null before they've been saved ────────────────────

    [Fact]
    public async Task GetStep1_BeforeSave_ReturnsNull()
    {
        await _svc.GetOrCreateWizardStateAsync(); // create the row but never save step 1
        Assert.Null(await _svc.GetStep1InterfacesAsync());
    }

    [Fact]
    public async Task GetStep2_BeforeSave_ReturnsNull()
    {
        await _svc.GetOrCreateWizardStateAsync();
        Assert.Null(await _svc.GetStep2LanAsync());
    }

    // ── CurrentStep advance ────────────────────────────────────────────

    [Fact]
    public async Task SetCurrentStep_PersistsAdvance()
    {
        await _svc.GetOrCreateWizardStateAsync();
        await _svc.SetCurrentStepAsync(3);

        var s = await _svc.GetOrCreateWizardStateAsync();
        Assert.Equal(3, s.CurrentStep);
    }
}
