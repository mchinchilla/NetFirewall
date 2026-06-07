using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Services.Processes;
using Xunit;

namespace NetFirewall.Tests.Network;

/// <summary>
/// Pure-function coverage of <see cref="DebianInterfacesConfigService.GenerateConfigAsync"/>.
/// The Apply/Restart paths shell out via IProcessRunner and live with their own
/// integration tests; here we pin the on-disk format that goes into
/// <c>/etc/network/interfaces.d/60-netfirewall-*</c>.
/// </summary>
public class DebianInterfacesConfigServiceTests
{
    private readonly DebianInterfacesConfigService _svc = new(
        new Mock<IProcessRunner>().Object,
        NullLogger<DebianInterfacesConfigService>.Instance);

    private static FwInterface IfaceStatic(string name = "eth0") => new()
    {
        Id = Guid.NewGuid(),
        Name = name,
        AddressingMode = "static",
        IpAddress = IPAddress.Parse("192.168.1.10"),
        SubnetMask = IPAddress.Parse("255.255.255.0"),
        Gateway = IPAddress.Parse("192.168.1.1")
    };

    // ── header / autostart ─────────────────────────────────────────────

    [Fact]
    public async Task Header_AlwaysIncludesManagedComment()
    {
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic());
        Assert.Contains("# Managed by NetFirewall - Do not edit manually", cfg);
    }

    [Fact]
    public async Task DescriptionRendersAsCommentWhenSet()
    {
        var iface = IfaceStatic();
        iface.Description = "uplink to ISP";
        var cfg = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("# uplink to ISP", cfg);
    }

    [Fact]
    public async Task AutoStartTrue_EmitsAutoLine()
    {
        var iface = IfaceStatic();
        iface.AutoStart = true;
        var cfg = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("auto eth0", cfg);
        Assert.DoesNotContain("allow-hotplug eth0", cfg);
    }

    [Fact]
    public async Task AutoStartFalse_EmitsAllowHotplugLine()
    {
        var iface = IfaceStatic();
        iface.AutoStart = false;
        var cfg = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("allow-hotplug eth0", cfg);
        Assert.DoesNotContain("auto eth0", cfg);
    }

    // ── addressing modes ───────────────────────────────────────────────

    [Fact]
    public async Task DhcpMode_EmitsInetDhcp_AndOmitsStaticFields()
    {
        var iface = IfaceStatic();
        iface.AddressingMode = "dhcp";
        var cfg = await _svc.GenerateConfigAsync(iface);

        Assert.Contains("iface eth0 inet dhcp", cfg);
        Assert.DoesNotContain("address 192.168.1.10", cfg);
        Assert.DoesNotContain("gateway", cfg);
    }

    [Fact]
    public async Task DisabledMode_EmitsInetManual()
    {
        var iface = IfaceStatic();
        iface.AddressingMode = "disabled";
        var cfg = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("iface eth0 inet manual", cfg);
    }

    [Fact]
    public async Task StaticMode_EmitsAddressNetmaskGateway()
    {
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic());

        Assert.Contains("iface eth0 inet static", cfg);
        Assert.Contains("address 192.168.1.10", cfg);
        Assert.Contains("netmask 255.255.255.0", cfg);
        Assert.Contains("gateway 192.168.1.1", cfg);
    }

    [Fact]
    public async Task StaticMode_EmitsDnsNameservers_SpaceSeparated()
    {
        var iface = IfaceStatic();
        iface.DnsServers = new[] { IPAddress.Parse("8.8.8.8"), IPAddress.Parse("1.1.1.1") };
        var cfg = await _svc.GenerateConfigAsync(iface);

        Assert.Contains("dns-nameservers 8.8.8.8 1.1.1.1", cfg);
    }

    // ── VLAN ────────────────────────────────────────────────────────────

    [Fact]
    public async Task VlanInterface_EmitsVlanRawDevice()
    {
        var iface = IfaceStatic("eth0.100");
        iface.VlanId = 100;
        iface.VlanParent = "eth0";
        var cfg = await _svc.GenerateConfigAsync(iface);

        Assert.Contains("iface eth0.100 inet static", cfg);
        Assert.Contains("vlan-raw-device eth0", cfg);
    }

    [Fact]
    public async Task NonVlanInterface_DoesNotEmitVlanRawDevice()
    {
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic());
        Assert.DoesNotContain("vlan-raw-device", cfg);
    }

    // ── optional knobs ─────────────────────────────────────────────────

    [Fact]
    public async Task MtuEmittedWhenSet_AndOmittedWhenNull()
    {
        var iface = IfaceStatic();
        iface.Mtu = 1492;
        Assert.Contains("mtu 1492", await _svc.GenerateConfigAsync(iface));

        iface.Mtu = null;
        Assert.DoesNotContain("mtu ", await _svc.GenerateConfigAsync(iface));
    }

    [Fact]
    public async Task MacOverrideEmittedWhenSet()
    {
        var iface = IfaceStatic();
        iface.MacAddress = "aa:bb:cc:dd:ee:ff";
        var cfg = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("hwaddress ether aa:bb:cc:dd:ee:ff", cfg);
    }

    [Fact]
    public async Task MetricEmittedOnlyWhenGatewaySet()
    {
        var iface = IfaceStatic();
        iface.Metric = 100;
        Assert.Contains("metric 100", await _svc.GenerateConfigAsync(iface));

        // Same metric, no gateway → metric must NOT appear (it's gateway-related).
        iface.Gateway = null;
        Assert.DoesNotContain("metric 100", await _svc.GenerateConfigAsync(iface));
    }

    // ── static routes ──────────────────────────────────────────────────

    [Fact]
    public async Task EnabledRoute_EmitsBothUpAndDownLines()
    {
        var iface = IfaceStatic();
        var routes = new[]
        {
            new FwStaticRoute
            {
                Destination = "10.20.0.0/16",
                Gateway = IPAddress.Parse("192.168.1.254"),
                Metric = 50,
                Enabled = true
            }
        };
        var cfg = await _svc.GenerateConfigAsync(iface, routes);

        Assert.Contains("up ip route add 10.20.0.0/16 via 192.168.1.254 metric 50 dev eth0 || true", cfg);
        Assert.Contains("down ip route del 10.20.0.0/16 via 192.168.1.254 dev eth0 || true", cfg);
    }

    [Fact]
    public async Task DisabledRoute_IsSkipped()
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
                Destination = "10.0.0.0/8",
                Gateway = null,
                Metric = 10,
                Enabled = true
            }
        };
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic(), routes);

        // Note: the current generator emits a stray space where "via" would be —
        // pinning that as the contract so a future rewrite is intentional.
        Assert.Contains("up ip route add 10.0.0.0/8  metric 10 dev eth0 || true", cfg);
        Assert.Contains("down ip route del 10.0.0.0/8  dev eth0 || true", cfg);
    }

    [Fact]
    public async Task NullRouteCollection_DoesNotThrow()
    {
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic(), routes: null);
        Assert.Contains("iface eth0 inet static", cfg);
    }

    // ── ParseAddressingMode — read the DECLARED mode (fixes the wizard's
    //    static-vs-DHCP guesswork that got ens192/ens224 backwards) ──

    private const string SampleInterfaces = """
        # /etc/network/interfaces
        auto lo
        iface lo inet loopback

        auto ens192
        iface ens192 inet static
            address 154.12.104.135
            netmask 255.255.255.0
            gateway 154.12.104.134

        allow-hotplug ens224
        iface ens224 inet dhcp
        """;

    [Fact]
    public void ParseAddressingMode_Static_interface()
        => Assert.Equal("static", DebianInterfacesConfigService.ParseAddressingMode(SampleInterfaces, "ens192"));

    [Fact]
    public void ParseAddressingMode_Dhcp_interface()
        => Assert.Equal("dhcp", DebianInterfacesConfigService.ParseAddressingMode(SampleInterfaces, "ens224"));

    [Fact]
    public void ParseAddressingMode_Loopback_is_null()
        => Assert.Null(DebianInterfacesConfigService.ParseAddressingMode(SampleInterfaces, "lo"));

    [Fact]
    public void ParseAddressingMode_UnknownInterface_is_null()
        => Assert.Null(DebianInterfacesConfigService.ParseAddressingMode(SampleInterfaces, "ens999"));

    [Fact]
    public void ParseAddressingMode_Manual_maps_to_disabled()
        => Assert.Equal("disabled", DebianInterfacesConfigService.ParseAddressingMode("iface eth9 inet manual", "eth9"));

    [Fact]
    public void ParseAddressingMode_LastStanzaWins()
    {
        // A later stanza (e.g. from interfaces.d concatenated) overrides an earlier one.
        const string cfg = "iface eth0 inet dhcp\niface eth0 inet static\n";
        Assert.Equal("static", DebianInterfacesConfigService.ParseAddressingMode(cfg, "eth0"));
    }

    [Fact]
    public void ParseAddressingMode_IgnoresCommentsAndPartialNameMatches()
    {
        const string cfg = "# iface eth0 inet dhcp\niface eth00 inet dhcp\n";
        // "eth0" must NOT match the commented line nor the "eth00" interface.
        Assert.Null(DebianInterfacesConfigService.ParseAddressingMode(cfg, "eth0"));
    }
}
