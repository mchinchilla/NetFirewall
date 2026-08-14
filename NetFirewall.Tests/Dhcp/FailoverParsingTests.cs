using NetFirewall.Services.Dhcp;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Coverage for <see cref="FailoverService.TryParseMacToBytes"/> — the strict
/// MAC parser that replaced a lenient version which silently produced
/// 00:00:00:00:00:00 for anything unparseable, collapsing malformed clients
/// into a single load-balancing bucket AND a single lease row on the peer.
/// </summary>
public class FailoverParsingTests
{
    private static byte[] Parse(string mac, out bool ok)
    {
        var buf = new byte[6];
        ok = FailoverService.TryParseMacToBytes(mac, buf);
        return buf;
    }

    [Theory]
    [InlineData("aa:bb:cc:dd:ee:ff")]
    [InlineData("AA:BB:CC:DD:EE:FF")]
    [InlineData("aa-bb-cc-dd-ee-ff")]
    [InlineData("Aa:bB-cC:Dd-Ee:fF")] // mixed separators + case
    public void ValidMacs_ParseToSameBytes(string mac)
    {
        var bytes = Parse(mac, out var ok);

        Assert.True(ok);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF }, bytes);
    }

    [Theory]
    [InlineData("")]
    [InlineData("aabbccddeeff")]        // no separators → one 12-char part
    [InlineData("aa:bb:cc:dd:ee")]      // 5 parts
    [InlineData("aa:bb:cc:dd:ee:ff:00")] // 7 parts
    [InlineData("zz:bb:cc:dd:ee:ff")]   // non-hex
    [InlineData("a:bb:cc:dd:ee:ff")]    // 1-char part
    [InlineData("aaa:bb:cc:dd:ee:f")]   // 3-char part
    public void InvalidMacs_Rejected(string mac)
    {
        Parse(mac, out var ok);

        Assert.False(ok);
    }

    [Fact]
    public void ZeroMac_IsValidAndDistinctFromParseFailure()
    {
        // 00:00:00:00:00:00 is a legal (if odd) MAC — it must parse as
        // SUCCESS, distinguishable from the failure case.
        var bytes = Parse("00:00:00:00:00:00", out var ok);

        Assert.True(ok);
        Assert.Equal(new byte[6], bytes);
    }
}
