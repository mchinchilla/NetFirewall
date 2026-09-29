using System.ComponentModel.DataAnnotations;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Web.Models.Network;

namespace NetFirewall.Tests.Wol;

/// <summary>Web half of Wake-on-LAN: form validation (rule #4) and what the ARP table is allowed to claim.</summary>
public class WolWebModelTests
{
    private static List<ValidationResult> Validate(object model)
    {
        var results = new List<ValidationResult>();
        Validator.TryValidateObject(model, new ValidationContext(model), results, validateAllProperties: true);
        return results;
    }

    // ── presence ───────────────────────────────────────────────────────

    [Theory]
    [InlineData("REACHABLE", "online")]
    [InlineData("STALE", "idle")]
    [InlineData("DELAY", "checking")]
    [InlineData("FAILED", "offline")]
    [InlineData("INCOMPLETE", "offline")]
    public void Presence_MapsTheNeighbourState(string state, string label)
    {
        Assert.Equal(label, WolPresence.From(new NeighborEntry("192.168.10.20", "00:11:32:ab:cd:ef", "ens256", state)).Label);
    }

    [Fact]
    public void Presence_AbsentMac_IsNotSeen()
    {
        var p = WolPresence.For("00:11:32:AB:CD:EF", [new NeighborEntry("192.168.10.9", "aa:bb:cc:00:00:01", "ens256", "REACHABLE")]);
        Assert.Equal("not seen", p.Label);
        Assert.Null(p.Ip);
    }

    [Fact]
    public void Presence_MostAliveEntryWins_AndMatchesIgnoringCase()
    {
        // ip -j neigh prints lower-case; an old FAILED row for a previous address must not hide the live one.
        var p = WolPresence.For("00:11:32:AB:CD:EF",
        [
            new NeighborEntry("192.168.10.30", "00:11:32:ab:cd:ef", "ens256", "FAILED"),
            new NeighborEntry("192.168.10.20", "00:11:32:ab:cd:ef", "ens256", "REACHABLE"),
        ]);
        Assert.Equal("online", p.Label);
        Assert.Equal("192.168.10.20", p.Ip);
    }

    // ── forms ──────────────────────────────────────────────────────────

    [Fact]
    public void DeviceForm_Valid()
    {
        Assert.Empty(Validate(new WolDeviceFormViewModel { Name = "nas", MacAddress = "0011.32ab.cdef", Interface = "ens256" }));
    }

    [Theory]
    [InlineData("", "001132ABCDEF", "ens256", 9, nameof(WolDeviceFormViewModel.Name))]
    [InlineData("nas", "01:00:5E:00:00:FB", "ens256", 9, nameof(WolDeviceFormViewModel.MacAddress))]
    [InlineData("nas", "001132ABCDEF", "", 9, nameof(WolDeviceFormViewModel.Interface))]
    [InlineData("nas", "001132ABCDEF", "ens256 && x", 9, nameof(WolDeviceFormViewModel.Interface))]
    [InlineData("nas", "001132ABCDEF", "ens256", 0, nameof(WolDeviceFormViewModel.Port))]
    public void DeviceForm_FlagsTheOffendingField(string name, string mac, string iface, int port, string field)
    {
        var errors = Validate(new WolDeviceFormViewModel { Name = name, MacAddress = mac, Interface = iface, Port = port });
        Assert.Contains(errors, e => e.MemberNames.Contains(field));
    }

    [Fact]
    public void WakeForm_NeedsAnInterfaceOrAnIpHint()
    {
        Assert.Contains(Validate(new WolWakeFormViewModel { MacAddress = "001132ABCDEF" }),
            e => e.MemberNames.Contains(nameof(WolWakeFormViewModel.Interface)));
        Assert.Empty(Validate(new WolWakeFormViewModel { MacAddress = "001132ABCDEF", IpHint = "192.168.10.20" }));
        Assert.Empty(Validate(new WolWakeFormViewModel { MacAddress = "001132ABCDEF", Interface = "ens256" }));
    }

    [Theory]
    [InlineData("10.1")]
    [InlineData("192.168.10.20/32")]
    [InlineData("fe80::1")]
    public void WakeForm_IpHintMustBeADottedQuad(string hint)
    {
        Assert.Contains(Validate(new WolWakeFormViewModel { MacAddress = "001132ABCDEF", IpHint = hint }),
            e => e.MemberNames.Contains(nameof(WolWakeFormViewModel.IpHint)));
    }
}
