using System.Net;
using System.Text.Json;
using NetFirewall.Services.Monitoring;
using Xunit;

namespace NetFirewall.Tests.Monitoring;

/// <summary>
/// Pure-mapping coverage for <see cref="IpAsnResolver.MapResponse"/> — turning an
/// ip.guide JSON response into the <c>ip_asn_cache</c> row, no HTTP/DB needed.
/// The success fixture is the EXACT response the user captured for 154.12.104.135.
/// </summary>
public sealed class IpAsnResolverMappingTests
{
    private static IpAsnResolver.IpGuideResponse? Parse(string json)
        => JsonSerializer.Deserialize<IpAsnResolver.IpGuideResponse>(json);

    [Fact]
    public void MapResponse_maps_real_ipguide_success()
    {
        // Verbatim from `curl -sL ip.guide/154.12.104.135`.
        const string json = """
        {
          "ip": "154.12.104.135",
          "network": {
            "cidr": "154.12.104.0/21",
            "autonomous_system": {
              "asn": 273189,
              "name": "CA NETWORK S.A. DE C.V.",
              "organization": "CA NETWORK S.A. DE C.V.",
              "country": "HN",
              "rir": "LACNIC"
            }
          },
          "location": { "city": "Tegucigalpa", "country": "Honduras" }
        }
        """;

        var row = IpAsnResolver.MapResponse(IPAddress.Parse("154.12.104.135"), Parse(json));

        Assert.True(row.Ok);
        Assert.Equal("154.12.104.0/21", row.Prefix);   // whole prefix cached, not /32
        Assert.Equal("AS273189", row.Asn);
        Assert.Equal("CA NETWORK S.A. DE C.V.", row.Org);
        Assert.Equal("HN", row.Country);
        Assert.Equal("Tegucigalpa", row.City);
    }

    [Fact]
    public void MapResponse_falls_back_to_name_when_org_missing()
    {
        const string json = """
        {"network":{"cidr":"8.8.8.0/24","autonomous_system":{"asn":15169,"name":"GOOGLE","country":"US"}}}
        """;

        var row = IpAsnResolver.MapResponse(IPAddress.Parse("8.8.8.8"), Parse(json));

        Assert.True(row.Ok);
        Assert.Equal("AS15169", row.Asn);
        Assert.Equal("GOOGLE", row.Org); // name used when organization absent
        Assert.Null(row.City);
    }

    [Fact]
    public void MapResponse_caches_failed_slash32_when_body_null()
    {
        var row = IpAsnResolver.MapResponse(IPAddress.Parse("203.0.113.7"), null);

        Assert.False(row.Ok);
        Assert.Equal("203.0.113.7/32", row.Prefix);
        Assert.Null(row.Asn);
    }

    [Fact]
    public void MapResponse_caches_failed_when_cidr_missing()
    {
        // Network present but no CIDR / no AS → treat as failure.
        const string json = """{"network":{"autonomous_system":{"asn":0}}}""";

        var row = IpAsnResolver.MapResponse(IPAddress.Parse("198.51.100.3"), Parse(json));

        Assert.False(row.Ok);
        Assert.Equal("198.51.100.3/32", row.Prefix);
    }
}
