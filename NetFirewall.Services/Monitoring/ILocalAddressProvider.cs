using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetFirewall.Services.Monitoring;

/// <summary>
/// Enumerates the host's own IP addresses (every interface + loopback). Used by
/// the conntrack sampler to recognise the firewall's own WAN/LAN IPs so they're
/// never recorded as a traffic destination — conntrack reply tuples carry our
/// WAN IP as <c>dst</c> after SNAT, which is not a real egress destination.
/// Behind an interface so it can be mocked in tests (CLAUDE.md rule 8).
/// </summary>
public interface ILocalAddressProvider
{
    /// <summary>Snapshot of the host's own IPv4 addresses.</summary>
    IReadOnlySet<IPAddress> GetLocalAddresses();
}

/// <summary>Reads addresses from the OS via <see cref="NetworkInterface"/>.</summary>
public sealed class LocalAddressProvider : ILocalAddressProvider
{
    public IReadOnlySet<IPAddress> GetLocalAddresses()
    {
        var set = new HashSet<IPAddress> { IPAddress.Loopback };
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.OperationalStatus != OperationalStatus.Up) continue;
            foreach (var ua in nic.GetIPProperties().UnicastAddresses)
            {
                if (ua.Address.AddressFamily == AddressFamily.InterNetwork)
                    set.Add(ua.Address);
            }
        }
        return set;
    }
}
