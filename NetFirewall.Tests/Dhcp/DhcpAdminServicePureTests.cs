using System.Net;
using NetFirewall.Services.Dhcp;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Pure coverage of <see cref="DhcpAdminService.CalculatePoolSize"/>.
/// Regression focus: an inverted range used to underflow the uint subtraction
/// into a huge negative int (pool 10.0.0.20→10.0.0.10 reported -9), corrupting
/// every stat derived from TotalPoolSize; IPv6 input read 4 of 16 bytes.
/// </summary>
public class DhcpAdminServicePureTests
{
    private static int Size(string start, string end) =>
        DhcpAdminService.CalculatePoolSize(IPAddress.Parse(start), IPAddress.Parse(end));

    [Theory]
    [InlineData("10.0.0.10", "10.0.0.10", 1)]      // single-address pool
    [InlineData("10.0.0.10", "10.0.0.11", 2)]      // adjacent
    [InlineData("10.0.0.0", "10.0.0.255", 256)]    // full /24 — off-by-one guard
    [InlineData("10.0.0.100", "10.0.0.200", 101)]  // typical pool
    [InlineData("10.0.0.255", "10.0.1.0", 2)]      // octet boundary
    public void ValidRanges_InclusiveCount(string start, string end, int expected) =>
        Assert.Equal(expected, Size(start, end));

    [Fact]
    public void InvertedRange_ReturnsZero_NotNegative() =>
        Assert.Equal(0, Size("10.0.0.20", "10.0.0.10"));

    [Fact]
    public void Ipv6Input_ReturnsZero_NotGarbage() =>
        Assert.Equal(0, DhcpAdminService.CalculatePoolSize(
            IPAddress.Parse("fe80::1"), IPAddress.Parse("fe80::ff")));

    [Fact]
    public void EntireIpv4Space_ClampsToIntMaxValue() =>
        Assert.Equal(int.MaxValue, Size("0.0.0.0", "255.255.255.255"));
}
