using System.Net;
using System.Text;
using System.Text.Json;

namespace NetFirewall.Models.Dhcp;

public static class DhcpOptionExtensions
{
    public static DhcpOption CreateOption(DhcpOptionCode code, byte[] data)
    {
        return new DhcpOption { Code = (byte)code, Data = data };
    }

    public static DhcpOption CreateOption(DhcpOptionCode code, string data)
    {
        return new DhcpOption { Code = (byte)code, Data = Encoding.ASCII.GetBytes(data) };
    }

    /// <summary>
    /// Encode domain names using RFC 1035 format for Option 119 (Domain Search List).
    /// Each label is prefixed with its length byte, domain ends with 0x00.
    /// </summary>
    /// <param name="domains">Comma or space-separated domain names</param>
    /// <returns>RFC 1035 encoded byte array</returns>
    public static byte[] EncodeDomainSearchList(string? domains)
    {
        if (string.IsNullOrWhiteSpace(domains))
            return [];

        using var ms = new MemoryStream();

        // Split by comma or space
        var domainList = domains.Split([',', ' ', ';'], StringSplitOptions.RemoveEmptyEntries);

        foreach (var domain in domainList)
        {
            var trimmed = domain.Trim().TrimEnd('.');
            if (string.IsNullOrEmpty(trimmed))
                continue;

            // Split domain into labels
            var labels = trimmed.Split('.');
            foreach (var label in labels)
            {
                if (label.Length > 63)
                    throw new ArgumentException($"Label '{label}' exceeds 63 characters");

                // Length byte + label
                ms.WriteByte((byte)label.Length);
                var labelBytes = Encoding.ASCII.GetBytes(label.ToLowerInvariant());
                ms.Write(labelBytes, 0, labelBytes.Length);
            }

            // Null terminator for this domain
            ms.WriteByte(0);
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Encode classless static routes per RFC 3442 for Option 121.
    /// Format: [prefix_length][significant_octets][gateway_ip]
    /// </summary>
    /// <param name="routesJson">JSON array of routes: [{"network": "10.0.0.0/8", "gateway": "192.168.1.1"}]</param>
    /// <returns>RFC 3442 encoded byte array</returns>
    public static byte[] EncodeClasslessStaticRoutes(string? routesJson)
    {
        if (string.IsNullOrWhiteSpace(routesJson))
            return [];

        try
        {
            var routes = JsonSerializer.Deserialize<DhcpStaticRoute[]>(routesJson);
            if (routes == null || routes.Length == 0)
                return [];

            return EncodeClasslessStaticRoutes(routes);
        }
        catch (JsonException)
        {
            return [];
        }
    }

    /// <summary>
    /// Encode classless static routes per RFC 3442 for Option 121.
    /// </summary>
    public static byte[] EncodeClasslessStaticRoutes(DhcpStaticRoute[] routes)
    {
        if (routes.Length == 0)
            return [];

        using var ms = new MemoryStream();

        foreach (var route in routes)
        {
            var (networkAddress, prefixLength) = route.ParseNetwork();
            var gateway = route.GetGateway();

            // Write prefix length
            ms.WriteByte((byte)prefixLength);

            // Calculate significant octets (number of octets needed for the prefix)
            var significantOctets = (prefixLength + 7) / 8;

            // Write only significant octets of the network address
            var networkBytes = networkAddress.GetAddressBytes();
            ms.Write(networkBytes, 0, significantOctets);

            // Write gateway address (always 4 bytes)
            var gatewayBytes = gateway.GetAddressBytes();
            ms.Write(gatewayBytes, 0, 4);
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Encode IP address list for multi-IP options (DNS, NTP, etc.)
    /// </summary>
    public static byte[] EncodeIpAddressList(IPAddress[]? addresses)
    {
        if (addresses == null || addresses.Length == 0)
            return [];

        var result = new byte[addresses.Length * 4];
        for (int i = 0; i < addresses.Length; i++)
        {
            addresses[i].GetAddressBytes().CopyTo(result, i * 4);
        }
        return result;
    }

    /// <summary>
    /// Encode a 32-bit integer in network byte order
    /// </summary>
    public static byte[] EncodeInt32NetworkOrder(int value)
    {
        var networkOrder = IPAddress.HostToNetworkOrder(value);
        return
        [
            (byte)(networkOrder >> 24),
            (byte)(networkOrder >> 16),
            (byte)(networkOrder >> 8),
            (byte)networkOrder
        ];
    }

    /// <summary>
    /// Encode a 16-bit integer in network byte order
    /// </summary>
    public static byte[] EncodeInt16NetworkOrder(short value)
    {
        var networkOrder = IPAddress.HostToNetworkOrder(value);
        return
        [
            (byte)(networkOrder >> 8),
            (byte)networkOrder
        ];
    }

    /// <summary>
    /// Parse domain search list from RFC 1035 encoded bytes
    /// </summary>
    public static string[] DecodeDomainSearchList(byte[] data)
    {
        var domains = new List<string>();
        int offset = 0;

        while (offset < data.Length)
        {
            var domain = new StringBuilder();

            while (offset < data.Length && data[offset] != 0)
            {
                int labelLength = data[offset++];
                if (offset + labelLength > data.Length)
                    break;

                if (domain.Length > 0)
                    domain.Append('.');

                domain.Append(Encoding.ASCII.GetString(data, offset, labelLength));
                offset += labelLength;
            }

            if (offset < data.Length && data[offset] == 0)
            {
                offset++; // Skip null terminator
            }

            if (domain.Length > 0)
            {
                domains.Add(domain.ToString());
            }
        }

        return [.. domains];
    }

    /// <summary>
    /// Parse classless static routes from RFC 3442 encoded bytes
    /// </summary>
    public static DhcpStaticRoute[] DecodeClasslessStaticRoutes(byte[] data)
    {
        var routes = new List<DhcpStaticRoute>();
        int offset = 0;

        while (offset < data.Length)
        {
            if (offset >= data.Length)
                break;

            int prefixLength = data[offset++];
            int significantOctets = (prefixLength + 7) / 8;

            if (offset + significantOctets + 4 > data.Length)
                break;

            // Read network address (padded with zeros)
            var networkBytes = new byte[4];
            Array.Copy(data, offset, networkBytes, 0, significantOctets);
            offset += significantOctets;

            // Read gateway
            var gatewayBytes = new byte[4];
            Array.Copy(data, offset, gatewayBytes, 0, 4);
            offset += 4;

            routes.Add(new DhcpStaticRoute
            {
                Network = $"{new IPAddress(networkBytes)}/{prefixLength}",
                Gateway = new IPAddress(gatewayBytes).ToString()
            });
        }

        return [.. routes];
    }
}
