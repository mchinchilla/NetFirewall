using System.Net;

namespace NetFirewall.Services.Monitoring;

/// <summary>
/// Pure IP-range predicates shared by the conntrack sampler and the ASN resolver.
/// No platform dependency (unlike <see cref="ConntrackSamplerService"/>, which is
/// linux-only), so this lives on its own and is freely callable/testable anywhere.
/// </summary>
public static class IpRanges
{
    /// <summary>RFC1918 / loopback / link-local / CGNAT — never a real Internet
    /// destination, so the sampler doesn't count it and the resolver doesn't look
    /// it up. IPv4 only for now (top-talkers are LAN-IPv4).</summary>
    public static bool IsPrivate(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;
        var b = ip.GetAddressBytes();
        if (b.Length != 4) return false;
        return b[0] == 10                                       // 10.0.0.0/8
            || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)        // 172.16.0.0/12
            || (b[0] == 192 && b[1] == 168)                     // 192.168.0.0/16
            || (b[0] == 169 && b[1] == 254)                     // 169.254.0.0/16 link-local
            || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);      // 100.64.0.0/10 CGNAT
    }
}
