using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Tests.Infra;
using Xunit;

namespace NetFirewall.Tests.Firewall;

/// <summary>
/// Coverage for the corona of the firewall: <see cref="FirewallService.GenerateNftablesConfigAsync"/>.
/// We use real Postgres + the real CRUD methods to insert state, then assert
/// against the rendered <c>nft</c> script. Network-object/service resolvers are
/// stubbed to return literals verbatim so this suite stays focused on the
/// generator's own logic, not the resolution layer (which has its own tests).
/// </summary>
[Collection("Postgres")]
public sealed class FirewallServiceGeneratorTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private FirewallService _svc = null!;
    private readonly Mock<INetworkObjectResolver> _objectResolver = new();
    private readonly Mock<INetworkServiceResolver> _serviceResolver = new();

    public FirewallServiceGeneratorTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();

        // Resolvers: return inputs verbatim. Real resolvers have their own tests.
        _objectResolver.Setup(r => r.ResolveAsync(It.IsAny<IEnumerable<string>>(), It.IsAny<CancellationToken>()))
            .Returns<IEnumerable<string>, CancellationToken>((inputs, _) =>
                Task.FromResult<IReadOnlyList<string>>(inputs.ToList()));
        _serviceResolver.Setup(r => r.ResolveAsync(It.IsAny<IEnumerable<string>>(), It.IsAny<CancellationToken>()))
            .Returns<IEnumerable<string>, CancellationToken>((inputs, _) =>
                Task.FromResult<IReadOnlyList<string>>(inputs.ToList()));

        _svc = new FirewallService(
            _pg.DataSource,
            _objectResolver.Object,
            _serviceResolver.Object,
            NullLogger<FirewallService>.Instance);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private async Task<FwInterface> CreateInterfaceAsync(string name, string type = "LAN") =>
        await _svc.CreateInterfaceAsync(new FwInterface
        {
            Name = name,
            Type = type,
            AddressingMode = "static",
            Enabled = true,
            AutoStart = true
        });

    // ── skeleton: tables, chains, header ───────────────────────────────

    [Fact]
    public async Task Generate_OnEmptyDb_EmitsHeaderFlushAndAllChainsWithDefaultPolicies()
    {
        var cfg = await _svc.GenerateNftablesConfigAsync();

        // Header + flush
        Assert.StartsWith("#!/usr/sbin/nft -f", cfg);
        Assert.Contains("flush ruleset", cfg);

        // NAT table is always emitted (even when empty)
        Assert.Contains("table ip nat {", cfg);
        Assert.Contains("chain prerouting {", cfg);
        Assert.Contains("type nat hook prerouting priority dstnat; policy accept;", cfg);
        Assert.Contains("chain postrouting {", cfg);
        Assert.Contains("type nat hook postrouting priority srcnat; policy accept;", cfg);

        // Filter table with three chains and default-drop on input/forward.
        Assert.Contains("table ip filter {", cfg);
        Assert.Contains("type filter hook input priority filter; policy drop;", cfg);
        Assert.Contains("iif lo accept", cfg);                 // loopback bypass
        Assert.Contains("type filter hook forward priority filter; policy drop;", cfg);
        Assert.Contains("type filter hook output priority filter; policy accept;", cfg);

        // Mangle table only when there are rules — empty DB → no mangle table.
        Assert.DoesNotContain("table ip mangle", cfg);
    }

    // ── filter rules ───────────────────────────────────────────────────

    [Fact]
    public async Task Generate_EnabledFilterRule_AppearsInCorrectChain()
    {
        var iface = await CreateInterfaceAsync("eth0", "WAN");
        await _svc.CreateFilterRuleAsync(new FwFilterRule
        {
            Chain = "input",
            Action = "accept",
            Protocol = "tcp",
            InterfaceInId = iface.Id,
            DestinationPorts = new[] { "22" },
            ConnectionState = new[] { "new", "established" },
            Description = "ssh allow",
            Priority = 10,
            Enabled = true
        });

        var cfg = await _svc.GenerateNftablesConfigAsync();

        // Rule should land in the input chain.
        var inputChain = ExtractChain(cfg, "input");
        Assert.Contains("iif eth0", inputChain);
        Assert.Contains("tcp", inputChain);
        Assert.Contains("dport", inputChain);
        Assert.Contains("22", inputChain);
        Assert.Contains("accept", inputChain);
    }

    [Fact]
    public async Task Generate_DisabledFilterRule_IsNotEmitted()
    {
        await _svc.CreateFilterRuleAsync(new FwFilterRule
        {
            Chain = "input",
            Action = "drop",
            Protocol = "tcp",
            DestinationPorts = new[] { "23" },
            Description = "telnet drop",
            Enabled = false
        });

        var cfg = await _svc.GenerateNftablesConfigAsync();

        // Match the actual emitted form ("tcp dport 23"), not just "23",
        // because the header timestamp may legitimately contain "23"
        // (e.g. "Generated: 2026-04-27T23:21:25Z").
        Assert.DoesNotContain("dport 23", cfg);
        Assert.DoesNotContain("telnet drop", cfg);
    }

    [Fact]
    public async Task Generate_FilterRulesEmittedInPriorityOrder()
    {
        // Two rules in the same chain — lower priority number renders first.
        await _svc.CreateFilterRuleAsync(new FwFilterRule
        {
            Chain = "input", Action = "accept", Protocol = "tcp",
            DestinationPorts = new[] { "1234" },   // marker port
            Priority = 200, Enabled = true
        });
        await _svc.CreateFilterRuleAsync(new FwFilterRule
        {
            Chain = "input", Action = "accept", Protocol = "tcp",
            DestinationPorts = new[] { "9876" },   // marker port
            Priority = 50, Enabled = true
        });

        var cfg = await _svc.GenerateNftablesConfigAsync();

        var iLow  = cfg.IndexOf("9876", StringComparison.Ordinal);
        var iHigh = cfg.IndexOf("1234", StringComparison.Ordinal);
        Assert.True(iLow > 0 && iHigh > 0, "both rule markers should be present");
        Assert.True(iLow < iHigh, "priority=50 rule should render before priority=200");
    }

    [Fact]
    public async Task Generate_RuleOnDisabledSchedule_IsSkipped()
    {
        var schedSvc = new ScheduleService(_pg.DataSource, NullLogger<ScheduleService>.Instance);

        // Schedule that is *enabled* but its window matches no day → not active now.
        var sched = await schedSvc.CreateAsync(new FwSchedule
        {
            Name = "never",
            DaysOfWeek = new[] { 0 },
            StartTime = TimeSpan.FromHours(3),
            EndTime = TimeSpan.FromHours(4),
            // Use a far-east timezone so the window is unlikely to coincide with "now"
            // — but the safer disable: flip the schedule's Enabled flag.
            Timezone = "UTC",
            Enabled = false
        });

        await _svc.CreateFilterRuleAsync(new FwFilterRule
        {
            Chain = "input", Action = "accept", Protocol = "tcp",
            DestinationPorts = new[] { "5566" },
            ScheduleId = sched.Id,
            Enabled = true
        });

        var cfg = await _svc.GenerateNftablesConfigAsync();

        Assert.DoesNotContain("5566", cfg);
    }

    [Fact]
    public async Task Generate_RuleOnAlwaysActiveSchedule_IsEmitted()
    {
        var schedSvc = new ScheduleService(_pg.DataSource, NullLogger<ScheduleService>.Instance);
        var sched = await schedSvc.CreateAsync(new FwSchedule
        {
            Name = "always",
            DaysOfWeek = new[] { 0, 1, 2, 3, 4, 5, 6 },
            StartTime = TimeSpan.Zero,
            EndTime = new TimeSpan(23, 59, 0),
            Timezone = "UTC",
            Enabled = true
        });

        await _svc.CreateFilterRuleAsync(new FwFilterRule
        {
            Chain = "input", Action = "accept", Protocol = "tcp",
            DestinationPorts = new[] { "7788" },
            ScheduleId = sched.Id,
            Enabled = true
        });

        var cfg = await _svc.GenerateNftablesConfigAsync();

        Assert.Contains("7788", cfg);
    }

    [Fact]
    public async Task Generate_NullScheduleId_AlwaysEmitsRule()
    {
        await _svc.CreateFilterRuleAsync(new FwFilterRule
        {
            Chain = "input", Action = "accept", Protocol = "tcp",
            DestinationPorts = new[] { "8899" },
            ScheduleId = null,   // always-on
            Enabled = true
        });

        var cfg = await _svc.GenerateNftablesConfigAsync();

        Assert.Contains("8899", cfg);
    }

    // ── port forwards (DNAT) ───────────────────────────────────────────

    [Fact]
    public async Task Generate_EnabledPortForward_AppearsInPreroutingChain()
    {
        var wan = await CreateInterfaceAsync("eth0", "WAN");
        await _svc.CreatePortForwardAsync(new FwPortForward
        {
            Description = "web",
            Protocol = "tcp",
            InterfaceId = wan.Id,
            ExternalPortStart = 8080,
            InternalIp = IPAddress.Parse("10.0.0.10"),
            InternalPort = 80,
            Enabled = true
        });

        var cfg = await _svc.GenerateNftablesConfigAsync();
        var prerouting = ExtractChain(cfg, "prerouting");

        Assert.Contains("iif eth0", prerouting);
        Assert.Contains("tcp", prerouting);
        Assert.Contains("8080", prerouting);
        Assert.Contains("dnat to 10.0.0.10:80", prerouting);
    }

    [Fact]
    public async Task Generate_DisabledPortForward_IsNotEmitted()
    {
        await _svc.CreatePortForwardAsync(new FwPortForward
        {
            Protocol = "tcp",
            ExternalPortStart = 4321,
            InternalIp = IPAddress.Parse("10.0.0.10"),
            InternalPort = 80,
            Enabled = false
        });

        var cfg = await _svc.GenerateNftablesConfigAsync();

        Assert.DoesNotContain("4321", cfg);
    }

    // ── NAT ────────────────────────────────────────────────────────────

    [Fact]
    public async Task Generate_MasqueradeRule_AppearsInPostroutingChain()
    {
        var wan = await CreateInterfaceAsync("eth0", "WAN");
        await _svc.CreateNatRuleAsync(new FwNatRule
        {
            Type = "masquerade",
            SourceNetwork = "192.168.1.0/24",
            OutputInterfaceId = wan.Id,
            Enabled = true
        });

        var cfg = await _svc.GenerateNftablesConfigAsync();
        var post = ExtractChain(cfg, "postrouting");

        Assert.Contains("oif eth0", post);
        Assert.Contains("192.168.1.0/24", post);
        Assert.Contains("masquerade", post);
    }

    [Fact(Skip = "fw_nat_rules.source_network is column type cidr — Postgres rejects " +
                  "non-CIDR values (object names) at INSERT, so the 'unresolvable' code " +
                  "path in the generator is currently unreachable. Documenting as a known " +
                  "schema/code mismatch: either widen the column to text, or move object-name " +
                  "references to a separate field with a join. Tracking separately.")]
    public async Task Generate_NatWithUnresolvableSource_RendersSkipComment()
    {
        // Intentionally empty — see Skip reason above. When the schema is widened
        // (or a sibling text-typed column is added), reactivate this test to pin
        // the "honest skip" comment behavior in GenerateNftablesConfigAsync.
        await Task.CompletedTask;
    }

    // ── mangle table ───────────────────────────────────────────────────

    [Fact]
    public async Task Generate_NoMangleRules_OmitsMangleTableEntirely()
    {
        // Add unrelated state — should still skip mangle.
        await CreateInterfaceAsync("eth0", "LAN");
        await _svc.CreateFilterRuleAsync(new FwFilterRule
        {
            Chain = "input", Action = "accept", Enabled = true
        });

        var cfg = await _svc.GenerateNftablesConfigAsync();

        Assert.DoesNotContain("table ip mangle", cfg);
    }

    [Fact]
    public async Task Generate_MangleRule_EmitsMarkThenReturn()
    {
        var mark = await _svc.CreateTrafficMarkAsync(new FwTrafficMark
        {
            Name = "VPN_WG0", MarkValue = 0x500, RouteTable = "wg0"
        });
        await _svc.CreateMangleRuleAsync(new FwMangleRule
        {
            Chain = "prerouting", Priority = 80, Enabled = true,
            MarkId = mark.Id, SourceAddresses = new[] { "192.168.99.66" },
            Description = "host → VPN"
        });

        var cfg = await _svc.GenerateNftablesConfigAsync();

        // The mark must be followed by `return` so a later, broader rule can't
        // overwrite it (regression: 0.0.0.0/0 → WAN1 clobbered specific marks).
        Assert.Contains("meta mark set 0x500 return", cfg);
    }

    [Fact]
    public async Task Generate_MangleRules_SpecificRuleOrderedBeforeBroaderByPriority()
    {
        var vpn  = await _svc.CreateTrafficMarkAsync(new FwTrafficMark { Name = "VPN_WG0", MarkValue = 0x500 });
        var wan1 = await _svc.CreateTrafficMarkAsync(new FwTrafficMark { Name = "WAN1",    MarkValue = 0x100 });

        // Insert the broad rule first to prove ordering is by Priority, not insert order.
        await _svc.CreateMangleRuleAsync(new FwMangleRule
        {
            Chain = "prerouting", Priority = 100, Enabled = true,
            MarkId = wan1.Id, SourceAddresses = new[] { "192.168.99.0/24" }, Description = "LAN → WAN1"
        });
        await _svc.CreateMangleRuleAsync(new FwMangleRule
        {
            Chain = "prerouting", Priority = 80, Enabled = true,
            MarkId = vpn.Id, SourceAddresses = new[] { "192.168.99.66" }, Description = "host → VPN"
        });

        var cfg = await _svc.GenerateNftablesConfigAsync();

        var vpnPos  = cfg.IndexOf("meta mark set 0x500 return", StringComparison.Ordinal);
        var wan1Pos = cfg.IndexOf("meta mark set 0x100 return", StringComparison.Ordinal);
        Assert.True(vpnPos >= 0 && wan1Pos >= 0, "both marks must be rendered");
        Assert.True(vpnPos < wan1Pos, "lower priority value (VPN, 80) must precede the broader WAN1 (100)");
    }

    // ── helpers ────────────────────────────────────────────────────────

    /// <summary>
    /// Pulls the body of a named chain from the rendered config. Lets tests
    /// assert against rule placement without false positives from siblings.
    /// </summary>
    private static string ExtractChain(string cfg, string chainName)
    {
        var marker = $"chain {chainName} {{";
        var start = cfg.IndexOf(marker, StringComparison.Ordinal);
        Assert.True(start >= 0, $"chain '{chainName}' not found in config");
        // Walk forward to the matching '}'.
        var depth = 0;
        var i = cfg.IndexOf('{', start);
        var end = i;
        for (; end < cfg.Length; end++)
        {
            if (cfg[end] == '{') depth++;
            else if (cfg[end] == '}') { depth--; if (depth == 0) break; }
        }
        return cfg.Substring(start, end - start + 1);
    }
}
