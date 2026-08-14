using System.Net;
using NetFirewall.Services.Dhcp;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Pure coverage of the CIDR pre-parser behind subnet-by-IP matching.
/// Regression focus: a subnet whose <c>subnet_mask</c> column is NULL used to
/// be silently unmatchable by giaddr/ciaddr/requested-ip even though its
/// "10.0.0.0/24" network string fully specifies the mask.
/// </summary>
public class DhcpSubnetServiceCidrTests
{
    private static bool Matches(string ip, DhcpSubnetService.ParsedCidr cidr) =>
        DhcpSubnetService.IpMatchesNetwork(IPAddress.Parse(ip).GetAddressBytes(), cidr);

    [Fact]
    public void ExplicitMask_TakesPrecedence()
    {
        var cidr = DhcpSubnetService.TryParseCidr("10.1.0.0/24", IPAddress.Parse("255.255.0.0"));

        Assert.NotNull(cidr);
        // /16 semantics from the explicit mask, not /24 from the string.
        Assert.True(Matches("10.1.200.5", cidr!.Value));
    }

    [Fact]
    public void NullMask_DerivedFromPrefix()
    {
        var cidr = DhcpSubnetService.TryParseCidr("10.1.2.0/24", null);

        Assert.NotNull(cidr);
        Assert.True(Matches("10.1.2.77", cidr!.Value));
        Assert.False(Matches("10.1.3.77", cidr.Value));
    }

    [Fact]
    public void PrefixZero_MatchesEverything()
    {
        var cidr = DhcpSubnetService.TryParseCidr("0.0.0.0/0", null);

        Assert.NotNull(cidr);
        Assert.True(Matches("1.2.3.4", cidr!.Value));
        Assert.True(Matches("255.255.255.255", cidr.Value));
    }

    [Fact]
    public void Prefix32_MatchesExactlyOneHost()
    {
        var cidr = DhcpSubnetService.TryParseCidr("10.0.0.5/32", null);

        Assert.NotNull(cidr);
        Assert.True(Matches("10.0.0.5", cidr!.Value));
        Assert.False(Matches("10.0.0.6", cidr.Value));
    }

    [Theory]
    [InlineData("10.0.0.0")]        // no prefix, no mask → underspecified
    [InlineData("10.0.0.0/33")]     // prefix out of range
    [InlineData("10.0.0.0/-1")]
    [InlineData("10.0.0.0/abc")]
    [InlineData("not-an-ip/24")]
    public void Invalid_ReturnsNull(string network) =>
        Assert.Null(DhcpSubnetService.TryParseCidr(network, null));

    [Fact]
    public void NoPrefix_ButExplicitMask_StillWorks()
    {
        var cidr = DhcpSubnetService.TryParseCidr("192.168.7.0", IPAddress.Parse("255.255.255.0"));

        Assert.NotNull(cidr);
        Assert.True(Matches("192.168.7.42", cidr!.Value));
    }

    [Fact]
    public void MaskedComparison_UsesNetworkBits_NotRawEquality()
    {
        // Network stored with host bits set ("10.0.0.1/24") still matches its
        // /24 because both sides are masked before comparing.
        var cidr = DhcpSubnetService.TryParseCidr("10.0.0.1/24", null);

        Assert.NotNull(cidr);
        Assert.True(Matches("10.0.0.200", cidr!.Value));
    }
}
