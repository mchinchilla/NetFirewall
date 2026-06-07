using NetFirewall.Services.Setup;
using NetFirewall.Web.Models.Setup;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// Pure-mapper coverage for the Step 1 → Step 2 derivation. Two behaviors the
/// wizard got wrong before:
///   1. Step 2 must derive the LAN subnet from the interface's ACTUAL config when
///      it already has an IP — not invent 192.168.10.x.
///   2. A clone/spoof MAC entered in Step 1 must flow into the service DTO.
/// </summary>
public sealed class WizardMappersTests
{
    private static Step1ViewModel Step1With(params Step1RowViewModel[] rows) =>
        new() { Interfaces = rows.ToList() };

    private static Step1RowViewModel Lan(string name, string? ip, string? mask, string mode = "static") => new()
    {
        Name = name, Role = "lan", AddressingMode = mode,
        IpAddress = ip, SubnetMask = mask,
    };

    // ── #1: LAN subnet derives from the real interface config ──────────────

    [Fact]
    public void Step2_DerivesLanSubnetFromExistingInterfaceConfig()
    {
        // ens256 is really on 192.168.99.1/24 — Step 2 must use THAT, not 192.168.10.x.
        var step1 = Step1With(Lan("ens256", "192.168.99.1", "255.255.255.0"));

        var step2 = ((List<NetFirewall.Models.Setup.WizardLanConfig>?)null).ToViewModel(step1);

        var lan = Assert.Single(step2.Lans);
        Assert.Equal("192.168.99.0/24", lan.NetworkCidr);
        Assert.Equal("192.168.99.1", lan.ServerIp);          // the LAN's own IP = gateway
        Assert.Equal("255.255.255.0", lan.SubnetMask);
        // DHCP pool must live INSIDE 192.168.99.0/24, not 192.168.10.x.
        Assert.StartsWith("192.168.99.", lan.DhcpRangeStart);
        Assert.StartsWith("192.168.99.", lan.DhcpRangeEnd);
    }

    [Fact]
    public void Step2_SuggestsFreeRange_OnlyWhenLanHasNoAddress()
    {
        // No IP on the LAN → free to suggest a 192.168.x.0/24.
        var step1 = Step1With(Lan("eth1", ip: null, mask: null, mode: "dhcp"));

        var step2 = ((List<NetFirewall.Models.Setup.WizardLanConfig>?)null).ToViewModel(step1);

        var lan = Assert.Single(step2.Lans);
        Assert.StartsWith("192.168.", lan.NetworkCidr);
        Assert.EndsWith("/24", lan.NetworkCidr);
    }

    [Fact]
    public void Step2_DoesNotSuggestRangeOverlappingTheLansOwnNetwork()
    {
        // A LAN already on 192.168.10.0/24 must keep 10.x, even though that's the
        // first slot the old NextFreeSlash24() would have picked.
        var step1 = Step1With(Lan("ens256", "192.168.10.1", "255.255.255.0"));

        var step2 = ((List<NetFirewall.Models.Setup.WizardLanConfig>?)null).ToViewModel(step1);

        var lan = Assert.Single(step2.Lans);
        Assert.Equal("192.168.10.0/24", lan.NetworkCidr);
        Assert.Equal("192.168.10.1", lan.ServerIp);
    }

    // ── #2: clone/spoof MAC flows Step 1 → service DTO ─────────────────────

    [Fact]
    public void ToServiceModel_CarriesSpoofMac_WhenProvided()
    {
        var step1 = Step1With(new Step1RowViewModel
        {
            Name = "ens256", Role = "lan", AddressingMode = "static",
            IpAddress = "192.168.99.1", SubnetMask = "255.255.255.0",
            MacAddress = "00:0C:29:FF:32:70",          // detected (hardware) MAC
            SpoofMacAddress = "DE:AD:BE:EF:00:01",      // operator override
        });

        var cfg = Assert.Single(step1.ToServiceModel());
        Assert.Equal("DE:AD:BE:EF:00:01", cfg.MacAddress);
    }

    [Fact]
    public void ToServiceModel_NullMac_WhenSpoofEmpty_KeepsHardwareMac()
    {
        var step1 = Step1With(new Step1RowViewModel
        {
            Name = "ens256", Role = "lan", AddressingMode = "dhcp",
            MacAddress = "00:0C:29:FF:32:70",
            SpoofMacAddress = null,
        });

        var cfg = Assert.Single(step1.ToServiceModel());
        Assert.Null(cfg.MacAddress); // null = don't override → NIC keeps its own MAC
    }
}
