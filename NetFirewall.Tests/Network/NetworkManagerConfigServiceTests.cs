using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Services.Processes;
using Xunit;

namespace NetFirewall.Tests.Network;

/// <summary>
/// Pure-function coverage of <see cref="NetworkManagerConfigService.GenerateConfigAsync"/>.
/// The keyfile format is parsed by NM with strict rules — section order, key=value
/// shape, and the address1=ip/prefix,gateway combo are all part of the contract.
/// </summary>
public class NetworkManagerConfigServiceTests
{
    private readonly NetworkManagerConfigService _svc = new(
        new Mock<IProcessRunner>().Object,
        NullLogger<NetworkManagerConfigService>.Instance);

    private static FwInterface IfaceStatic(string name = "eth0") => new()
    {
        Id = Guid.NewGuid(),
        Name = name,
        AddressingMode = "static",
        IpAddress = IPAddress.Parse("192.168.1.10"),
        SubnetMask = IPAddress.Parse("255.255.255.0"),
        Gateway = IPAddress.Parse("192.168.1.1")
    };

    // ── header & connection block ──────────────────────────────────────

    [Fact]
    public async Task Header_AlwaysIncludesManagedComment()
    {
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic());
        Assert.Contains("# Managed by NetFirewall", cfg);
    }

    [Fact]
    public async Task ConnectionBlock_HasIdInterfaceTypeAutoconnect()
    {
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic());

        Assert.Contains("[connection]", cfg);
        Assert.Contains("id=netfirewall-eth0", cfg);
        Assert.Contains("interface-name=eth0", cfg);
        Assert.Contains("type=ethernet", cfg);
        Assert.Contains("autoconnect=true", cfg);
    }

    [Fact]
    public async Task AutoStartFalse_RendersAutoconnectFalse()
    {
        var iface = IfaceStatic();
        iface.AutoStart = false;
        var cfg = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("autoconnect=false", cfg);
    }

    [Fact]
    public async Task DescriptionRendersAsCommentWhenSet()
    {
        var iface = IfaceStatic();
        iface.Description = "uplink to ISP";
        var cfg = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("# uplink to ISP", cfg);
    }

    // ── deterministic UUID ─────────────────────────────────────────────

    [Fact]
    public async Task Uuid_IsDeterministicForTheSameInterfaceName()
    {
        var iface1 = IfaceStatic("eth0");
        var iface2 = IfaceStatic("eth0"); // different Id, same name
        var cfg1 = await _svc.GenerateConfigAsync(iface1);
        var cfg2 = await _svc.GenerateConfigAsync(iface2);

        var uuid1 = ExtractUuid(cfg1);
        var uuid2 = ExtractUuid(cfg2);
        Assert.Equal(uuid1, uuid2); // re-applying same name → same UUID, no orphans
    }

    [Fact]
    public async Task Uuid_DiffersForDifferentInterfaceNames()
    {
        var cfg1 = await _svc.GenerateConfigAsync(IfaceStatic("eth0"));
        var cfg2 = await _svc.GenerateConfigAsync(IfaceStatic("eth1"));

        Assert.NotEqual(ExtractUuid(cfg1), ExtractUuid(cfg2));
    }

    [Fact]
    public async Task Uuid_IsValidGuidWithRfc4122VariantBits()
    {
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic());
        var uuid = ExtractUuid(cfg);
        Assert.True(Guid.TryParse(uuid, out var parsed));

        // RFC 4122 §4.4 — variant bits in field 4 must be 10xxxxxx (top two = 0b10).
        // The variant byte is the 9th byte of the canonical (big-endian) GUID;
        // in .NET's Guid.ToByteArray() it lives at index 8.
        var bytes = parsed.ToByteArray();
        Assert.Equal(0x80, bytes[8] & 0xC0);
    }

    // ── ipv4 addressing modes ──────────────────────────────────────────

    [Fact]
    public async Task DhcpMode_EmitsMethodAuto_AndOmitsAddress()
    {
        var iface = IfaceStatic();
        iface.AddressingMode = "dhcp";
        var cfg = await _svc.GenerateConfigAsync(iface);

        Assert.Contains("[ipv4]", cfg);
        Assert.Contains("method=auto", cfg);
        Assert.DoesNotContain("address1=", cfg);
    }

    [Fact]
    public async Task DisabledMode_EmitsMethodDisabled()
    {
        var iface = IfaceStatic();
        iface.AddressingMode = "disabled";
        var cfg = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("method=disabled", cfg);
    }

    [Fact]
    public async Task StaticMode_EmitsMethodManualAndAddressWithGateway()
    {
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic());
        Assert.Contains("method=manual", cfg);
        // NM's keyfile shape: address1=<ip>/<prefix>,<gateway>
        Assert.Contains("address1=192.168.1.10/24,192.168.1.1", cfg);
    }

    [Fact]
    public async Task StaticMode_WithoutGateway_OmitsCommaGateway()
    {
        var iface = IfaceStatic();
        iface.Gateway = null;
        var cfg = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("address1=192.168.1.10/24", cfg);
        Assert.DoesNotContain("address1=192.168.1.10/24,", cfg);
    }

    [Fact]
    public async Task StaticMode_DnsServers_EmittedAsSemicolonList_WithIgnoreAutoDns()
    {
        var iface = IfaceStatic();
        iface.DnsServers = new[] { IPAddress.Parse("8.8.8.8"), IPAddress.Parse("1.1.1.1") };
        var cfg = await _svc.GenerateConfigAsync(iface);

        // NM keyfiles use ';'-separated lists with a trailing ';'.
        Assert.Contains("dns=8.8.8.8;1.1.1.1;", cfg);
        Assert.Contains("ignore-auto-dns=true", cfg);
    }

    [Fact]
    public async Task DhcpMode_OmitsDnsAndIgnoreAutoDns_EvenIfDnsServersSet()
    {
        var iface = IfaceStatic();
        iface.AddressingMode = "dhcp";
        iface.DnsServers = new[] { IPAddress.Parse("8.8.8.8") };
        var cfg = await _svc.GenerateConfigAsync(iface);

        Assert.DoesNotContain("dns=8.8.8.8", cfg);
        Assert.DoesNotContain("ignore-auto-dns=", cfg);
    }

    // ── ethernet vs vlan section ───────────────────────────────────────

    [Fact]
    public async Task NonVlanInterface_EmitsEthernetSection_AndNoVlanSection()
    {
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic());
        Assert.Contains("[ethernet]", cfg);
        Assert.DoesNotContain("[vlan]", cfg);
        Assert.Contains("type=ethernet", cfg);
    }

    [Fact]
    public async Task VlanInterface_EmitsVlanSection_AndNoEthernetSection_AndTypeVlan()
    {
        var iface = IfaceStatic("eth0.100");
        iface.VlanId = 100;
        iface.VlanParent = "eth0";
        var cfg = await _svc.GenerateConfigAsync(iface);

        Assert.Contains("type=vlan", cfg);
        Assert.Contains("[vlan]", cfg);
        Assert.Contains("id=100", cfg);
        Assert.Contains("parent=eth0", cfg);
        Assert.DoesNotContain("[ethernet]", cfg);
    }

    [Fact]
    public async Task EthernetSection_EmitsMtuAndClonedMacWhenSet()
    {
        var iface = IfaceStatic();
        iface.Mtu = 1492;
        iface.MacAddress = "aa:bb:cc:dd:ee:ff";
        var cfg = await _svc.GenerateConfigAsync(iface);

        Assert.Contains("mtu=1492", cfg);
        Assert.Contains("cloned-mac-address=aa:bb:cc:dd:ee:ff", cfg);
    }

    // ── ipv6 explicit-disable & metric ─────────────────────────────────

    [Fact]
    public async Task Ipv6_AlwaysExplicitlyDisabled()
    {
        // Defensive default — captures the deliberate "opt-in later from the UI" decision.
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic());
        Assert.Contains("[ipv6]", cfg);
        Assert.Contains("method=disabled", cfg);
    }

    [Fact]
    public async Task Metric_EmittedAsRouteMetricWhenSet()
    {
        var iface = IfaceStatic();
        iface.Metric = 200;
        var cfg = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("route-metric=200", cfg);
    }

    // ── static routes ──────────────────────────────────────────────────

    [Fact]
    public async Task EnabledRoutes_AreEmittedAsRouteN_WithSequentialIndex()
    {
        var routes = new[]
        {
            new FwStaticRoute { Destination = "10.0.0.0/8",  Gateway = IPAddress.Parse("192.168.1.254"), Metric = 50,  Enabled = true },
            new FwStaticRoute { Destination = "172.16.0.0/12", Gateway = IPAddress.Parse("192.168.1.254"), Metric = 100, Enabled = true }
        };
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic(), routes);

        Assert.Contains("route1=10.0.0.0/8,192.168.1.254,50", cfg);
        Assert.Contains("route2=172.16.0.0/12,192.168.1.254,100", cfg);
    }

    [Fact]
    public async Task DisabledRoutes_DoNotConsumeIndex()
    {
        var routes = new[]
        {
            new FwStaticRoute { Destination = "10.0.0.0/8",  Gateway = IPAddress.Parse("192.168.1.254"), Metric = 50,  Enabled = false },
            new FwStaticRoute { Destination = "172.16.0.0/12", Gateway = IPAddress.Parse("192.168.1.254"), Metric = 100, Enabled = true }
        };
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic(), routes);

        Assert.DoesNotContain("10.0.0.0/8", cfg);
        // The enabled route gets index 1, not 2.
        Assert.Contains("route1=172.16.0.0/12,192.168.1.254,100", cfg);
        Assert.DoesNotContain("route2=", cfg);
    }

    [Fact]
    public async Task RouteWithoutGateway_OmitsCommaGateway()
    {
        var routes = new[]
        {
            new FwStaticRoute { Destination = "10.0.0.0/8", Gateway = null, Metric = 50, Enabled = true }
        };
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic(), routes);
        Assert.Contains("route1=10.0.0.0/8,50", cfg);
    }

    [Fact]
    public async Task RouteWithEmptyDestination_IsSkipped()
    {
        var routes = new[]
        {
            new FwStaticRoute { Destination = "", Gateway = IPAddress.Parse("192.168.1.254"), Metric = 50, Enabled = true }
        };
        var cfg = await _svc.GenerateConfigAsync(IfaceStatic(), routes);
        Assert.DoesNotContain("route1=", cfg);
    }

    // ── path & validation helpers ──────────────────────────────────────

    [Fact]
    public void GetConfigFilePath_ReturnsNmKeyfilePathWithPrefix()
    {
        var path = _svc.GetConfigFilePath(IfaceStatic("eth1"));
        Assert.Equal("/etc/NetworkManager/system-connections/netfirewall-eth1.nmconnection", path);
    }

    [Fact]
    public async Task ValidateConfig_AcceptsKeyfileWithRequiredSections()
    {
        var ok = await _svc.ValidateConfigAsync(
            "[connection]\nid=x\ninterface-name=eth0\n[ipv4]\nmethod=auto\n");
        Assert.True(ok);
    }

    [Theory]
    [InlineData("")]
    [InlineData("[ipv4]\nmethod=auto")]              // missing [connection]
    [InlineData("[connection]\ninterface-name=eth0")] // missing [ipv4]
    [InlineData("[connection]\n[ipv4]\nmethod=auto")] // missing interface-name=
    public async Task ValidateConfig_RejectsKeyfileMissingRequiredFields(string config)
    {
        Assert.False(await _svc.ValidateConfigAsync(config));
    }

    // ── small parse helper ─────────────────────────────────────────────

    private static string ExtractUuid(string cfg)
    {
        foreach (var line in cfg.Split('\n'))
            if (line.StartsWith("uuid=")) return line[5..].Trim();
        throw new InvalidOperationException("uuid= line not found in keyfile output");
    }
}
