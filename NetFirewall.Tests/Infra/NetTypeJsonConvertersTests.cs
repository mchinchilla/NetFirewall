using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using NetFirewall.Models;
using NetFirewall.Models.Dhcp;
using NetFirewall.Models.Json;

namespace NetFirewall.Tests.Infra;

/// <summary>
/// Guards the JSON contract for entities carrying <see cref="IPAddress"/> /
/// <see cref="PhysicalAddress"/>. Without the converters, System.Text.Json
/// throws on IPAddress (ScopeId getter) — save endpoints committed the row,
/// then 500'd while writing the response body.
/// </summary>
public class NetTypeJsonConvertersTests
{
    private static JsonSerializerOptions Opts()
    {
        var o = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
        o.Converters.Add(new IPAddressJsonConverter());
        o.Converters.Add(new PhysicalAddressJsonConverter());
        return o;
    }

    [Fact]
    public void IPAddress_WithoutConverter_Throws_DocumentsTheBug()
    {
        Assert.ThrowsAny<Exception>(() => JsonSerializer.Serialize(IPAddress.Parse("192.168.99.4")));
    }

    [Fact]
    public void IPAddress_RoundTrips_AsDottedQuadString()
    {
        var json = JsonSerializer.Serialize(IPAddress.Parse("192.168.99.4"), Opts());
        Assert.Equal("\"192.168.99.4\"", json);
        Assert.Equal(IPAddress.Parse("192.168.99.4"), JsonSerializer.Deserialize<IPAddress>(json, Opts()));
    }

    [Fact]
    public void PhysicalAddress_Writes_ColonForm_And_ReadsBoth()
    {
        var mac = PhysicalAddress.Parse("00-0C-29-71-5E-67");
        var json = JsonSerializer.Serialize(mac, Opts());
        Assert.Equal("\"00:0C:29:71:5E:67\"", json);
        Assert.Equal(mac, JsonSerializer.Deserialize<PhysicalAddress>("\"00:0C:29:71:5E:67\"", Opts()));
        Assert.Equal(mac, JsonSerializer.Deserialize<PhysicalAddress>("\"00-0c-29-71-5e-67\"", Opts()));
    }

    [Fact]
    public void ReservationEnvelope_Serializes_WithConverters()
    {
        var envelope = ServiceResponse<DhcpMacReservation>.Ok(new DhcpMacReservation
        {
            Id = Guid.NewGuid(),
            MacAddress = PhysicalAddress.Parse("00-0C-29-71-5E-67"),
            ReservedIp = IPAddress.Parse("192.168.99.4"),
            Description = "TK1"
        }, "saved");

        var json = JsonSerializer.Serialize(envelope, Opts());
        Assert.Contains("\"192.168.99.4\"", json);
        Assert.Contains("\"00:0C:29:71:5E:67\"", json);
    }
}
