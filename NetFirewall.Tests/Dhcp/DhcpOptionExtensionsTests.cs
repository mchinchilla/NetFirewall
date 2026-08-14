using NetFirewall.Models.Dhcp;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Coverage for the RFC 1035 / RFC 3442 option encoders in
/// <see cref="DhcpOptionExtensions"/>. These run on the per-packet hot path
/// from admin-supplied config (domain search list, static routes) and on
/// decode paths fed by external bytes — both must be total functions:
/// skip-invalid, never throw, never over-read.
/// </summary>
public class DhcpOptionExtensionsTests
{
    // ── EncodeDomainSearchList (option 119) ────────────────────────────

    [Fact]
    public void DomainSearchList_SingleDomain_Rfc1035Encoded()
    {
        var bytes = DhcpOptionExtensions.EncodeDomainSearchList("corp.example");

        Assert.Equal(new byte[]
        {
            4, (byte)'c', (byte)'o', (byte)'r', (byte)'p',
            7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
            0
        }, bytes);
    }

    [Fact]
    public void DomainSearchList_MultipleSeparators_AllEncoded()
    {
        // Comma, space and semicolon are all accepted separators.
        var bytes = DhcpOptionExtensions.EncodeDomainSearchList("a.com,b.com c.com;d.com");
        var decoded = DhcpOptionExtensions.DecodeDomainSearchList(bytes);

        Assert.Equal(new[] { "a.com", "b.com", "c.com", "d.com" }, decoded);
    }

    [Fact]
    public void DomainSearchList_LowercasesLabels()
    {
        var decoded = DhcpOptionExtensions.DecodeDomainSearchList(
            DhcpOptionExtensions.EncodeDomainSearchList("MiXeD.ExAmPlE.COM"));

        Assert.Equal(new[] { "mixed.example.com" }, decoded);
    }

    [Fact]
    public void DomainSearchList_OverlongLabel_SkippedNotThrown()
    {
        // >63-char label is invalid per RFC 1035. The old encoder THREW here —
        // on the per-packet path that turned one config typo into a NAK for
        // every client on the subnet. Now the invalid domain is skipped.
        var longLabel = new string('x', 64);
        var bytes = DhcpOptionExtensions.EncodeDomainSearchList($"{longLabel}.example.com,valid.example.com");

        Assert.Equal(new[] { "valid.example.com" }, DhcpOptionExtensions.DecodeDomainSearchList(bytes));
    }

    [Fact]
    public void DomainSearchList_EmptyLabelFromDoubleDot_DomainSkipped()
    {
        // "a..b" contains a zero-length label — encoding it would embed an
        // early terminator and corrupt the option.
        var bytes = DhcpOptionExtensions.EncodeDomainSearchList("bad..domain,good.example");

        Assert.Equal(new[] { "good.example" }, DhcpOptionExtensions.DecodeDomainSearchList(bytes));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void DomainSearchList_Blank_ReturnsEmpty(string? input) =>
        Assert.Empty(DhcpOptionExtensions.EncodeDomainSearchList(input));

    [Fact]
    public void DomainSearchList_TrailingDot_Normalized()
    {
        var decoded = DhcpOptionExtensions.DecodeDomainSearchList(
            DhcpOptionExtensions.EncodeDomainSearchList("example.com."));

        Assert.Equal(new[] { "example.com" }, decoded);
    }

    // ── Classless static routes (option 121) ───────────────────────────

    [Fact]
    public void StaticRoutes_EncodeDecode_RoundTrips()
    {
        var routes = new[]
        {
            new DhcpStaticRoute { Network = "10.0.0.0/8", Gateway = "192.168.1.1" },
            new DhcpStaticRoute { Network = "172.16.0.0/16", Gateway = "192.168.1.2" },
            new DhcpStaticRoute { Network = "192.168.5.0/24", Gateway = "192.168.1.3" },
        };

        var decoded = DhcpOptionExtensions.DecodeClasslessStaticRoutes(
            DhcpOptionExtensions.EncodeClasslessStaticRoutes(routes));

        Assert.Equal(3, decoded.Length);
        Assert.Equal("10.0.0.0/8", decoded[0].Network);
        Assert.Equal("192.168.1.1", decoded[0].Gateway);
        Assert.Equal("172.16.0.0/16", decoded[1].Network);
        Assert.Equal("192.168.5.0/24", decoded[2].Network);
        Assert.Equal("192.168.1.3", decoded[2].Gateway);
    }

    [Fact]
    public void StaticRoutes_SignificantOctetsOnly_CompactEncoding()
    {
        // RFC 3442: a /8 destination uses exactly ONE descriptor octet.
        var bytes = DhcpOptionExtensions.EncodeClasslessStaticRoutes(new[]
        {
            new DhcpStaticRoute { Network = "10.0.0.0/8", Gateway = "1.2.3.4" }
        });

        // prefix(1) + significant octets(1) + gateway(4)
        Assert.Equal(6, bytes.Length);
        Assert.Equal(8, bytes[0]);
        Assert.Equal(10, bytes[1]);
    }

    [Fact]
    public void StaticRoutes_DefaultRoute_ZeroSignificantOctets()
    {
        var bytes = DhcpOptionExtensions.EncodeClasslessStaticRoutes(new[]
        {
            new DhcpStaticRoute { Network = "0.0.0.0/0", Gateway = "192.168.1.1" }
        });

        // prefix(1) + zero octets + gateway(4)
        Assert.Equal(5, bytes.Length);
        Assert.Equal(0, bytes[0]);
    }

    [Fact]
    public void StaticRoutes_DecodeMaliciousPrefixOver32_StopsWithoutThrowing()
    {
        // prefix 255 → 32 "significant octets" → the old decoder passed the
        // length check and blew up copying 32 bytes into a 4-byte array.
        var malicious = new byte[40];
        malicious[0] = 255;

        var decoded = DhcpOptionExtensions.DecodeClasslessStaticRoutes(malicious);

        Assert.Empty(decoded);
    }

    [Fact]
    public void StaticRoutes_DecodeTruncated_StopsCleanly()
    {
        // /24 route needs 3 + 4 bytes after the prefix — give it 2.
        var truncated = new byte[] { 24, 192, 168 };

        Assert.Empty(DhcpOptionExtensions.DecodeClasslessStaticRoutes(truncated));
    }

    [Fact]
    public void StaticRoutes_FromJson_InvalidJson_ReturnsEmpty() =>
        Assert.Empty(DhcpOptionExtensions.EncodeClasslessStaticRoutes("{not json"));

    [Fact]
    public void StaticRoutes_FromJson_ValidJson_Encodes()
    {
        // Property names are bound via [JsonPropertyName("network"/"gateway")].
        var bytes = DhcpOptionExtensions.EncodeClasslessStaticRoutes(
            """[{"network": "10.0.0.0/8", "gateway": "192.168.1.1"}]""");

        Assert.Equal(6, bytes.Length);
    }

    [Fact]
    public void StaticRoutes_MalformedRouteInList_SkippedNotThrown()
    {
        // One bad row in admin config must not prevent the valid routes from
        // encoding (and must not throw on the per-packet path).
        var routes = new[]
        {
            new DhcpStaticRoute { Network = "not-a-cidr", Gateway = "192.168.1.1" },
            new DhcpStaticRoute { Network = "10.0.0.0/8", Gateway = "192.168.1.1" },
        };

        var decoded = DhcpOptionExtensions.DecodeClasslessStaticRoutes(
            DhcpOptionExtensions.EncodeClasslessStaticRoutes(routes));

        Assert.Single(decoded);
        Assert.Equal("10.0.0.0/8", decoded[0].Network);
    }

    // ── Integer encoders ───────────────────────────────────────────────

    [Fact]
    public void EncodeInt32NetworkOrder_BigEndian()
    {
        Assert.Equal(new byte[] { 0x00, 0x01, 0x51, 0x80 },
            DhcpOptionExtensions.EncodeInt32NetworkOrder(86400));
    }

    [Fact]
    public void EncodeInt16NetworkOrder_BigEndian()
    {
        Assert.Equal(new byte[] { 0x05, 0xDC },
            DhcpOptionExtensions.EncodeInt16NetworkOrder(1500));
    }
}
