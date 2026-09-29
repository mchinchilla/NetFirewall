using NetFirewall.Models.Wol;

namespace NetFirewall.Tests.Wol;

public class MagicPacketAndMacTests
{
    // ── MagicPacket ────────────────────────────────────────────────────

    [Fact]
    public void Build_IsSixFfThenTheMacSixteenTimes()
    {
        byte[] mac = [0x00, 0x11, 0x32, 0xAB, 0xCD, 0xEF];

        var packet = MagicPacket.Build(mac);

        Assert.Equal(102, packet.Length);
        Assert.All(packet[..6], b => Assert.Equal(0xFF, b));
        for (var i = 0; i < 16; i++)
            Assert.Equal(mac, packet[(6 + i * 6)..(12 + i * 6)]);
    }

    [Fact]
    public void Build_RefusesAnythingButSixBytes()
    {
        Assert.Throws<ArgumentException>(() => MagicPacket.Build(new byte[5]));
        Assert.Throws<ArgumentException>(() => MagicPacket.Build(new byte[8]));
    }

    // ── MacAddressText ─────────────────────────────────────────────────

    [Theory]
    [InlineData("00:11:32:ab:cd:ef")]
    [InlineData("00-11-32-AB-CD-EF")]
    [InlineData("0011.32ab.cdef")]          // Cisco
    [InlineData("001132ABCDEF")]            // PhysicalAddress.ToString(), what the DHCP rows post
    [InlineData("  00:11:32:AB:CD:EF  ")]
    public void TryParse_AcceptsTheCommonSpellings_AndNormalises(string input)
    {
        Assert.True(MacAddressText.TryParse(input, out var bytes, out var normalized, out var error));
        Assert.Null(error);
        Assert.Equal("00:11:32:AB:CD:EF", normalized);
        Assert.Equal(new byte[] { 0x00, 0x11, 0x32, 0xAB, 0xCD, 0xEF }, bytes);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("00:11:32:ab:cd")]          // five octets
    [InlineData("00:11:32:ab:cd:eg")]       // not hex
    [InlineData("00:11:32:ab:cd:ef:01")]
    [InlineData("0011:32ab:cdef")]          // Cisco digits, wrong separator
    [InlineData("00:11:32.ab:cd:ef")]       // a dot where a pair separator belongs
    [InlineData("001132ABCDE")]
    public void TryParse_RejectsMalformed(string? input)
    {
        Assert.False(MacAddressText.TryParse(input, out _, out _, out var error));
        Assert.False(string.IsNullOrEmpty(error));
    }

    [Theory]
    [InlineData("00:00:00:00:00:00")]
    [InlineData("FF:FF:FF:FF:FF:FF")]       // broadcast
    [InlineData("01:00:5E:00:00:FB")]       // IPv4 multicast
    [InlineData("33:33:00:00:00:01")]       // IPv6 multicast
    public void TryParse_RejectsAddressesNoNicOwns(string input)
    {
        Assert.False(MacAddressText.TryParse(input, out _, out _, out var error));
        Assert.NotNull(error);
    }

    [Theory]
    [InlineData("00:11:32:ab:cd:ef", true)]
    [InlineData("0011.32ab.cdef", true)]
    [InlineData("001132ABCDEF", true)]
    [InlineData("00:11:32-ab:cd:ef", true)] // mixed separators: harmless, the server takes them too
    [InlineData("00:11:32:ab:cd", false)]
    [InlineData("0011:32ab:cdef", false)]
    public void Pattern_AgreesWithTheServerParserOnShape(string input, bool expected)
    {
        // The browser anchors the pattern as ^(?:…)$; mirror that here.
        var rx = new System.Text.RegularExpressions.Regex("^(?:" + MacAddressText.Pattern + ")$");
        Assert.Equal(expected, rx.IsMatch(input));
        Assert.Equal(expected, MacAddressText.TryParse(input, out _, out _, out _));
    }
}
