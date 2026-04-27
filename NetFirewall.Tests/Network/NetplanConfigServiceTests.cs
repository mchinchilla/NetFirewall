using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Services.Processes;
using Xunit;

namespace NetFirewall.Tests.Network;

/// <summary>
/// Pure-function coverage of <see cref="NetplanConfigService.GenerateConfigAsync"/>.
/// Validates the YAML-like text the service writes into <c>/etc/netplan/...</c>.
/// We don't parse the output as YAML — the layout itself is the contract,
/// since hand-rolled string concatenation is what the tool consumes.
/// </summary>
public class NetplanConfigServiceTests
{
    private readonly NetplanConfigService _svc = new(
        new Mock<IProcessRunner>().Object,
        NullLogger<NetplanConfigService>.Instance);

    private static FwInterface IfaceStatic(string name = "eth0") => new()
    {
        Id = Guid.NewGuid(),
        Name = name,
        AddressingMode = "static",
        IpAddress = IPAddress.Parse("192.168.1.10"),
        SubnetMask = IPAddress.Parse("255.255.255.0"),
        Gateway = IPAddress.Parse("192.168.1.1")
    };

    // ── header & version ───────────────────────────────────────────────

    [Fact]
    public async Task Header_IncludesNetworkVersion2_AndNetworkdRenderer()
    {
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic());
        Assert.Contains("# Managed by NetFirewall - Do not edit manually", cfg);
        Assert.Contains("network:", cfg);
        Assert.Contains("version: 2", cfg);
        Assert.Contains("renderer: networkd", cfg);
    }

    // ── interface section detection ────────────────────────────────────

    [Theory]
    [InlineData("eth0",  "ethernets")]
    [InlineData("eth1",  "ethernets")]
    [InlineData("ens18", "ethernets")]
    [InlineData("enp3s0","ethernets")]
    [InlineData("wlan0", "wifis")]
    [InlineData("wlp2s0","wifis")]
    [InlineData("bond0", "bonds")]
    [InlineData("br0",   "bridges")]
    [InlineData("tun0",  "ethernets")] // unknown prefix → defaults to ethernets
    public async Task Section_DerivedFromInterfaceNamePrefix(string name, string expectedSection)
    {
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic(name));
        Assert.Contains($"  {expectedSection}:", cfg);
        Assert.Contains($"    {name}:", cfg);
    }

    // ── addressing modes ───────────────────────────────────────────────

    [Fact]
    public async Task DhcpMode_EmitsDhcp4True()
    {
        var iface = IfaceStatic();
        iface.AddressingMode = "dhcp";
        var cfg = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("dhcp4: true", cfg);
        Assert.DoesNotContain("dhcp4: false", cfg);
        Assert.DoesNotContain("addresses:", cfg);
    }

    [Fact]
    public async Task DisabledMode_EmitsOptionalTrue()
    {
        var iface = IfaceStatic();
        iface.AddressingMode = "disabled";
        var cfg = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("optional: true", cfg);
    }

    [Fact]
    public async Task StaticMode_EmitsDhcp4False_AndAddressInCidrForm()
    {
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic());
        Assert.Contains("dhcp4: false", cfg);
        Assert.Contains("addresses:", cfg);
        Assert.Contains("- 192.168.1.10/24", cfg); // 255.255.255.0 → /24
    }

    [Theory]
    [InlineData("255.255.255.0",   24)]
    [InlineData("255.255.0.0",     16)]
    [InlineData("255.0.0.0",        8)]
    [InlineData("255.255.255.128", 25)]
    [InlineData("255.255.255.252", 30)]
    [InlineData("255.255.255.255", 32)]
    public async Task SubnetMaskConvertedToCidrPrefix(string mask, int expectedPrefix)
    {
        var iface = IfaceStatic();
        iface.SubnetMask = IPAddress.Parse(mask);
        var cfg = await _svc.GenerateConfigAsync(iface);
        Assert.Contains($"- 192.168.1.10/{expectedPrefix}", cfg);
    }

    // ── routes ──────────────────────────────────────────────────────────

    [Fact]
    public async Task GatewayPresent_EmitsDefaultRoute()
    {
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic());
        Assert.Contains("routes:", cfg);
        Assert.Contains("- to: default", cfg);
        Assert.Contains("via: 192.168.1.1", cfg);
    }

    [Fact]
    public async Task GatewayMetricEmittedWhenSet()
    {
        var iface = IfaceStatic();
        iface.Metric = 200;
        var cfg = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("metric: 200", cfg);
    }

    [Fact]
    public async Task NoGatewayAndNoExtraRoutes_OmitsRoutesBlock()
    {
        var iface = IfaceStatic();
        iface.Gateway = null;
        var cfg = await _svc.GenerateConfigAsync(iface);
        Assert.DoesNotContain("routes:", cfg);
    }

    [Fact]
    public async Task NoGatewayButExtraRoutes_StillEmitsRoutesBlock()
    {
        var iface = IfaceStatic();
        iface.Gateway = null;
        var routes = new[]
        {
            new FwStaticRoute
            {
                Destination = "10.20.0.0/16",
                Gateway = IPAddress.Parse("10.0.0.1"),
                Metric = 100,
                Enabled = true
            }
        };
        var cfg = await _svc.GenerateConfigAsync(iface, routes);

        Assert.Contains("routes:", cfg);
        Assert.Contains("- to: 10.20.0.0/16", cfg);
        Assert.Contains("via: 10.0.0.1", cfg);
        Assert.Contains("metric: 100", cfg);
        // No default route since no iface gateway.
        Assert.DoesNotContain("- to: default", cfg);
    }

    [Fact]
    public async Task DisabledRoutes_AreSkipped()
    {
        var routes = new[]
        {
            new FwStaticRoute
            {
                Destination = "10.20.0.0/16",
                Gateway = IPAddress.Parse("192.168.1.254"),
                Enabled = false
            }
        };
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic(), routes);
        Assert.DoesNotContain("10.20.0.0/16", cfg);
    }

    [Fact]
    public async Task RouteWithoutGateway_OmitsViaToken()
    {
        var routes = new[]
        {
            new FwStaticRoute
            {
                Destination = "169.254.0.0/16",
                Gateway = null,
                Metric = 10,
                Enabled = true
            }
        };
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic(), routes);

        Assert.Contains("- to: 169.254.0.0/16", cfg);
        // No `via:` line follows immediately for that route.
        var lines = cfg.Split('\n');
        var idx = Array.FindIndex(lines, l => l.Contains("- to: 169.254.0.0/16"));
        Assert.True(idx >= 0);
        Assert.DoesNotContain("via:", lines[idx + 1]); // next line should be metric, not via
    }

    // ── DNS ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task DnsServers_EmittedUnderNameservers()
    {
        var iface = IfaceStatic();
        iface.DnsServers = new[] { IPAddress.Parse("8.8.8.8"), IPAddress.Parse("1.1.1.1") };
        var cfg = await _svc.GenerateConfigAsync(iface);

        Assert.Contains("nameservers:", cfg);
        Assert.Contains("addresses:", cfg);
        Assert.Contains("- 8.8.8.8", cfg);
        Assert.Contains("- 1.1.1.1", cfg);
    }

    // ── optional knobs ─────────────────────────────────────────────────

    [Fact]
    public async Task DescriptionRendersAsComment()
    {
        var iface = IfaceStatic();
        iface.Description = "uplink to ISP";
        var cfg = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("# uplink to ISP", cfg);
    }

    [Fact]
    public async Task MtuEmittedWhenSet()
    {
        var iface = IfaceStatic();
        iface.Mtu = 1492;
        Assert.Contains("mtu: 1492", await _svc.GenerateConfigAsync(iface));
    }

    [Fact]
    public async Task MacOverrideEmittedWhenSet()
    {
        var iface = IfaceStatic();
        iface.MacAddress = "aa:bb:cc:dd:ee:ff";
        var cfg = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("macaddress: aa:bb:cc:dd:ee:ff", cfg);
    }

    [Fact]
    public async Task AutoStartFalse_EmitsOptionalTrue()
    {
        var iface = IfaceStatic();
        iface.AutoStart = false;
        var cfg = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("optional: true", cfg);
    }

    // ── path helper ────────────────────────────────────────────────────

    [Fact]
    public void GetConfigFilePath_ReturnsNetplanPathWithPrefix()
    {
        var path = _svc.GetConfigFilePath(IfaceStatic("eth1"));
        Assert.Equal("/etc/netplan/60-netfirewall-eth1.yaml", path);
    }
}
