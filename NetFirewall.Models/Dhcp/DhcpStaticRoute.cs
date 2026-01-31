using System.Net;
using System.Text.Json.Serialization;

namespace NetFirewall.Models.Dhcp;

/// <summary>
/// Represents a static route for DHCP Option 121 (Classless Static Routes - RFC 3442)
/// </summary>
public class DhcpStaticRoute
{
    /// <summary>
    /// Destination network in CIDR notation (e.g., "10.0.0.0/8")
    /// </summary>
    [JsonPropertyName("network")]
    public string Network { get; set; } = string.Empty;

    /// <summary>
    /// Gateway/router IP address for this route
    /// </summary>
    [JsonPropertyName("gateway")]
    public string Gateway { get; set; } = string.Empty;

    /// <summary>
    /// Parse CIDR notation and return network address and prefix length
    /// </summary>
    public (IPAddress NetworkAddress, int PrefixLength) ParseNetwork()
    {
        var parts = Network.Split('/');
        if (parts.Length != 2)
            throw new FormatException($"Invalid CIDR notation: {Network}");

        var networkAddress = IPAddress.Parse(parts[0]);
        var prefixLength = int.Parse(parts[1]);

        if (prefixLength < 0 || prefixLength > 32)
            throw new ArgumentOutOfRangeException(nameof(prefixLength), "Prefix length must be 0-32");

        return (networkAddress, prefixLength);
    }

    /// <summary>
    /// Get gateway as IPAddress
    /// </summary>
    public IPAddress GetGateway() => IPAddress.Parse(Gateway);
}
