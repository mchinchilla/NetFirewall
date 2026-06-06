using System.Text.Json;
using NetFirewall.Services.Monitoring;
using Xunit;

namespace NetFirewall.Tests.Monitoring;

/// <summary>
/// Pure-mapping coverage for <see cref="GeoIpLookupService.Map"/> — turning an
/// ip.guide JSON response into the <see cref="NetFirewall.Models.System.GeoIpInfo"/>
/// the login + connecting-from cards render, no HTTP/cache needed. The success
/// fixture is the EXACT response the user captured for 154.12.104.135, including
/// the timezone / lat-lon the background resolver drops.
/// </summary>
public sealed class GeoIpLookupMappingTests
{
    private static GeoIpLookupService.IpGuideResponse? Parse(string json)
        => JsonSerializer.Deserialize<GeoIpLookupService.IpGuideResponse>(json);

    [Fact]
    public void Map_maps_real_ipguide_success_with_timezone()
    {
        // Verbatim from `curl -sL ip.guide/154.12.104.135`.
        const string json = """
        {
          "ip": "154.12.104.135",
          "network": {
            "cidr": "154.12.104.0/21",
            "autonomous_system": {
              "asn": 273189,
              "name": "AS273189 - CA NETWORK S.A. DE C.V.",
              "organization": "CA NETWORK S.A. DE C.V.",
              "country": "HN",
              "rir": "LACNIC"
            }
          },
          "location": {
            "city": "Tegucigalpa",
            "country": "Honduras",
            "timezone": "America/Tegucigalpa",
            "latitude": 14.0828,
            "longitude": -87.2041
          }
        }
        """;

        var info = GeoIpLookupService.Map(Parse(json), forSelf: false);

        Assert.True(info.Ok);
        Assert.False(info.ForSelf);
        Assert.Equal("154.12.104.135", info.Ip);
        Assert.Equal("Tegucigalpa", info.City);
        Assert.Equal("HN", info.Country);                 // AS country (ISO-2)
        Assert.Equal("Honduras", info.CountryName);       // location country (full name)
        Assert.Equal("AS273189", info.Asn);
        Assert.Equal("CA NETWORK S.A. DE C.V.", info.Org);
        Assert.Equal("America/Tegucigalpa", info.Timezone);
        Assert.Equal(14.0828, info.Latitude);
        Assert.Equal(-87.2041, info.Longitude);
    }

    [Fact]
    public void Map_falls_back_to_as_name_when_org_missing()
    {
        const string json = """
        {"ip":"8.8.8.8","network":{"cidr":"8.8.8.0/24","autonomous_system":{"asn":15169,"name":"GOOGLE","country":"US"}}}
        """;

        var info = GeoIpLookupService.Map(Parse(json), forSelf: false);

        Assert.True(info.Ok);
        Assert.Equal("AS15169", info.Asn);
        Assert.Equal("GOOGLE", info.Org); // name used when organization absent
        Assert.Null(info.Timezone);
    }

    [Fact]
    public void Map_self_lookup_sets_for_self_flag()
    {
        // ip.guide bare endpoint echoes the requester's own public IP.
        const string json = """
        {"ip":"203.0.113.50","location":{"city":"Somewhere","country":"Nowhere","timezone":"UTC"}}
        """;

        var info = GeoIpLookupService.Map(Parse(json), forSelf: true);

        Assert.True(info.Ok);
        Assert.True(info.ForSelf);
        Assert.Equal("203.0.113.50", info.Ip);
        Assert.Equal("UTC", info.Timezone);
        Assert.Null(info.Asn); // no network block in this response
    }

    [Fact]
    public void Map_null_body_is_unavailable()
    {
        var info = GeoIpLookupService.Map(null, forSelf: false);

        Assert.False(info.Ok);
        Assert.Null(info.Ip);
        Assert.Null(info.City);
    }

    [Fact]
    public void Map_empty_body_is_unavailable_but_keeps_for_self_flag()
    {
        var info = GeoIpLookupService.Map(Parse("{}"), forSelf: true);

        Assert.False(info.Ok);
        Assert.True(info.ForSelf);
    }
}
