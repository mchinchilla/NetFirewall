using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Setup;
using NetFirewall.Services.Dhcp;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Setup;
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
    private SetupWizardService _svc = null!;

    public SetupWizardServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _svc = new SetupWizardService(
            _pg.DataSource, _firewall.Object, _subnets.Object,
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
            new() { Name = "eth0", Role = "wan_primary", UseDhcp = true },
            new() { Name = "eth1", Role = "lan", IpAddress = "10.0.0.1", SubnetMask = "255.255.255.0" }
        };

        await _svc.SaveStep1InterfacesAsync(input);

        var fetched = await _svc.GetStep1InterfacesAsync();
        Assert.NotNull(fetched);
        Assert.Equal(2, fetched!.Count);
        Assert.Equal("eth0", fetched[0].Name);
        Assert.Equal("wan_primary", fetched[0].Role);
        Assert.True(fetched[0].UseDhcp);
        Assert.Equal("eth1", fetched[1].Name);
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
