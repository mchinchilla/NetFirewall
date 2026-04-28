using System.Net;
using NetFirewall.Models.Firewall;
using NetFirewall.Tui.Screens;
using Xunit;

namespace NetFirewall.Tests.Tui;

/// <summary>
/// Pin the pure-function helpers inside <see cref="NetworkInterfacesScreen"/>.
/// The interactive Spectre.Console flows can't be unit-tested without a TTY,
/// but the bits that turn data into menu choices and validate user input are
/// straight functions and worth covering — they're where the silent bugs hide
/// (CIDR off-by-one, MAC regex too permissive, choice ordering).
/// </summary>
public class NetworkInterfacesScreenTests
{
    // ── BuildActionChoices ─────────────────────────────────────────────

    [Fact]
    public void BuildActionChoices_NoInterfaces_OnlyAddAndBack()
    {
        var choices = NetworkInterfacesScreen.BuildActionChoices(Array.Empty<FwInterface>());

        Assert.Equal(2, choices.Count);
        Assert.StartsWith("Add new", choices[0]);
        Assert.StartsWith("←", choices[^1]);
    }

    [Fact]
    public void BuildActionChoices_WithInterfaces_GroupsEditFirstThenApply()
    {
        // Order matters for usability: all Edits group together, then all
        // Applies. Mixing them ("Edit eth0", "Apply eth0", "Edit eth1"...)
        // makes the menu harder to scan when there are many NICs.
        var ifs = new[]
        {
            new FwInterface { Name = "eth0", Type = "WAN" },
            new FwInterface { Name = "eth1", Type = "LAN" }
        };

        var choices = NetworkInterfacesScreen.BuildActionChoices(ifs);

        // Layout: [Add, Edit:eth0, Edit:eth1, Apply:eth0, Apply:eth1, Back]
        Assert.Equal(6, choices.Count);
        Assert.StartsWith("Add new", choices[0]);
        Assert.Equal("Edit: eth0", choices[1]);
        Assert.Equal("Edit: eth1", choices[2]);
        Assert.Equal("Apply: eth0", choices[3]);
        Assert.Equal("Apply: eth1", choices[4]);
        Assert.StartsWith("←", choices[5]);
    }

    // ── MaskToCidrPrefix ───────────────────────────────────────────────

    [Theory]
    [InlineData("255.255.255.0", 24)]   // /24 standard home subnet
    [InlineData("255.255.255.255", 32)] // /32 single host
    [InlineData("255.255.255.252", 30)] // /30 point-to-point
    [InlineData("255.255.0.0", 16)]     // /16 class B
    [InlineData("255.0.0.0", 8)]        // /8 class A
    [InlineData("0.0.0.0", 0)]          // /0 default route
    [InlineData("255.255.255.128", 25)] // odd-byte boundary
    public void MaskToCidrPrefix_StandardMasks_ReturnRightBitCount(string maskStr, int expected)
    {
        var mask = IPAddress.Parse(maskStr);
        Assert.Equal(expected, NetworkInterfacesScreen.MaskToCidrPrefix(mask));
    }

    [Fact]
    public void MaskToCidrPrefix_NullMask_ReturnsZero()
    {
        // Defensive: an interface row may have no mask yet (just-created stub).
        // The renderer shouldn't NRE — it should print "0" and let the user
        // see something's off.
        Assert.Equal(0, NetworkInterfacesScreen.MaskToCidrPrefix(null));
    }

    // ── IsValidMac ─────────────────────────────────────────────────────

    [Theory]
    [InlineData("aa:bb:cc:dd:ee:ff")]   // lowercase + colons
    [InlineData("AA:BB:CC:DD:EE:FF")]   // uppercase + colons
    [InlineData("aa-bb-cc-dd-ee-ff")]   // dashes (some Linux distros render this way)
    [InlineData("01:23:45:67:89:0a")]   // mixed digits/letters
    public void IsValidMac_AcceptsCanonicalForms(string mac)
    {
        Assert.True(NetworkInterfacesScreen.IsValidMac(mac));
    }

    [Theory]
    [InlineData("")]                            // empty — caller decides separately
    [InlineData("aabbccddeeff")]                // missing separators (PhysicalAddress.ToString default)
    [InlineData("aa:bb:cc:dd:ee")]              // only 5 octets
    [InlineData("aa:bb:cc:dd:ee:ff:11")]        // 7 octets
    [InlineData("zz:bb:cc:dd:ee:ff")]           // non-hex chars
    [InlineData("aaa:bb:cc:dd:ee:ff")]          // 3-char octet
    [InlineData("aa.bb.cc.dd.ee.ff")]           // dot separator (not RFC)
    public void IsValidMac_RejectsMalformed(string mac)
    {
        Assert.False(NetworkInterfacesScreen.IsValidMac(mac));
    }

    [Fact]
    public void IsValidMac_TrimsWhitespace()
    {
        // Operators copy-paste; tolerate leading/trailing spaces. The screen
        // also lower-cases before saving, but this just checks the regex pass.
        Assert.True(NetworkInterfacesScreen.IsValidMac("  aa:bb:cc:dd:ee:ff  "));
    }
}
