using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace NetFirewall.Services.Dhcp;

/// <summary>This host's IPv4 addresses per interface — what the DHCP server identifies itself as.</summary>
public interface IInterfaceAddressProvider
{
    /// <summary>IPv4 addresses (with prefix length) configured on <paramref name="interfaceName"/>; empty when unknown.</summary>
    IReadOnlyList<(IPAddress Address, int PrefixLength)> GetIPv4(string interfaceName);
}

/// <summary>
/// Reads the OS interface table, cached for a few seconds: it is consulted for every reply, and
/// enumerating NICs costs far more than building the reply. An address change (DHCP on a WAN,
/// operator edit) is picked up on the next refresh.
/// </summary>
public sealed class InterfaceAddressProvider : IInterfaceAddressProvider
{
    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(15);
    private volatile Snapshot _snapshot = new(new Dictionary<string, (IPAddress, int)[]>(), DateTime.MinValue);

    private sealed record Snapshot(IReadOnlyDictionary<string, (IPAddress, int)[]> ByName, DateTime TakenUtc);

    public IReadOnlyList<(IPAddress Address, int PrefixLength)> GetIPv4(string interfaceName)
    {
        var snap = _snapshot;
        if (DateTime.UtcNow - snap.TakenUtc > Ttl) _snapshot = snap = Take();
        return snap.ByName.TryGetValue(interfaceName, out var list) ? list : [];
    }

    private static Snapshot Take()
    {
        var map = new Dictionary<string, (IPAddress, int)[]>(StringComparer.Ordinal);
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                var v4 = nic.GetIPProperties().UnicastAddresses
                    .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                    .Select(a => (a.Address, a.PrefixLength))
                    .ToArray();
                if (v4.Length > 0) map[nic.Name] = v4;
            }
        }
        catch (NetworkInformationException)
        {
            // Keep serving with the fallback identifier (the subnet router) rather than failing a reply.
        }
        return new Snapshot(map, DateTime.UtcNow);
    }
}
