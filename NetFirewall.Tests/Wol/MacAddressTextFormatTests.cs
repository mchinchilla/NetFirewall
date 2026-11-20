using NetFirewall.Models.Wol;
using NetFirewall.Web.Grids.Dhcp;
using Xunit;

namespace NetFirewall.Tests.Wol;

/// <summary>The single MAC formatter (Wake-on-LAN, LeaseCache warm-up, leases grid) keeps its exact output.</summary>
public sealed class MacAddressTextFormatTests
{
    private static readonly byte[] Mac = [0xAA, 0xBB, 0x0C, 0x1D, 0xEE, 0x0F];

    [Fact] public void Upper_IsTheCanonicalForm() => Assert.Equal("AA:BB:0C:1D:EE:0F", MacAddressText.Format(Mac));
    [Fact] public void Lower_ForDhcp() => Assert.Equal("aa:bb:0c:1d:ee:0f", MacAddressText.Format(Mac, lowercase: true));
    [Fact] public void Empty_IsEmpty() => Assert.Equal("", MacAddressText.Format([]));

    [Theory]
    [InlineData("AABB0C1DEE0F", "aa:bb:0c:1d:ee:0f")]
    [InlineData("aabb0c1dee0f", "aa:bb:0c:1d:ee:0f")]
    [InlineData("ZZBB0C1DEE0F", "ZZBB0C1DEE0F")]   // not hex → shown as-is, like before
    [InlineData("AABB", "AABB")]
    public void LeasesGrid_MacText(string raw, string expected) => Assert.Equal(expected, LeaseGridRow.MacText(raw));
}
