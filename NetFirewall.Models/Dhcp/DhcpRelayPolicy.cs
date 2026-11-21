using System.Collections.Frozen;
using System.Net;

namespace NetFirewall.Models.Dhcp;

/// <summary>What the server does with a relayed packet. Pure; built from dhcp_relay_agents.</summary>
public enum DhcpRelayVerdict
{
    /// <summary>Answer it; option 82 may drive class matching.</summary>
    Accept,
    /// <summary>Answer it, but don't let its option 82 choose a class or pool (still echoed).</summary>
    AcceptIgnoringOption82,
    /// <summary>Drop it in silence.</summary>
    Drop,
}

/// <summary>
/// The trusted-relay rule (RFC 3046, Security Considerations: option 82 is only as trustworthy
/// as whoever inserted it). With no trusted relay configured nothing changes. Once one is:
/// <list type="bullet">
/// <item>a relayed packet (giaddr ≠ 0) from a giaddr that isn't trusted is dropped;</item>
/// <item>a direct packet (giaddr = 0) carrying option 82 is still answered — snooping switches
/// insert exactly that — but its option 82 can't pick a class or pool any more (a client can
/// forge it). The option is still echoed so the switch can forward the reply.</item>
/// </list>
/// A relay listed as untrusted is refused even while no relay is trusted.
/// </summary>
public sealed class DhcpRelayPolicy
{
    public static readonly DhcpRelayPolicy Open = new(FrozenSet<IPAddress>.Empty, FrozenSet<IPAddress>.Empty);

    private readonly FrozenSet<IPAddress> _trusted;
    private readonly FrozenSet<IPAddress> _refused;

    public DhcpRelayPolicy(FrozenSet<IPAddress> trusted, FrozenSet<IPAddress> refused)
    {
        _trusted = trusted;
        _refused = refused;
    }

    public static DhcpRelayPolicy From(IEnumerable<DhcpRelayAgent> relays)
    {
        var list = relays as IReadOnlyCollection<DhcpRelayAgent> ?? relays.ToList();
        return new(list.Where(r => r.Trusted).Select(r => r.IpAddress).ToFrozenSet(),
                   list.Where(r => !r.Trusted).Select(r => r.IpAddress).ToFrozenSet());
    }

    /// <summary>True once at least one relay is trusted — from then on unlisted relays are dropped.</summary>
    public bool IsEnforced => _trusted.Count > 0;

    public DhcpRelayVerdict Evaluate(IPAddress? giaddr, bool hasOption82)
    {
        var relayed = giaddr is not null && !giaddr.Equals(IPAddress.Any);
        if (relayed)
        {
            if (_refused.Contains(giaddr!)) return DhcpRelayVerdict.Drop;
            if (!IsEnforced) return DhcpRelayVerdict.Accept;
            return _trusted.Contains(giaddr!) ? DhcpRelayVerdict.Accept : DhcpRelayVerdict.Drop;
        }
        return IsEnforced && hasOption82 ? DhcpRelayVerdict.AcceptIgnoringOption82 : DhcpRelayVerdict.Accept;
    }
}
