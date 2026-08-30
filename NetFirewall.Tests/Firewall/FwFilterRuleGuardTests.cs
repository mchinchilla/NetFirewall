using NetFirewall.Models.Firewall;
using Xunit;

namespace NetFirewall.Tests.Firewall;

/// <summary>
/// Coverage for <see cref="FwFilterRuleGuard"/> — the shared definition of
/// "this accept rule makes its chain's default-deny policy unreachable".
///
/// Pure logic, no Postgres. The three callers (FirewallService save, the nft
/// generator, and the Web rule form) all route through
/// <see cref="FwFilterRuleGuard.DescribeBypass"/>, so this suite is the one
/// place the definition is pinned down.
/// </summary>
public class FwFilterRuleGuardTests
{
    private static FwFilterRule Rule(
        string chain = "input",
        string action = "accept",
        string? protocol = "tcp",
        Guid? ifIn = null,
        Guid? ifOut = null,
        string[]? src = null,
        string[]? dst = null,
        string[]? ports = null,
        string[]? states = null,
        string? rate = null,
        bool enabled = true) => new()
    {
        Id = Guid.NewGuid(),
        Chain = chain,
        Action = action,
        Protocol = protocol,
        InterfaceInId = ifIn,
        InterfaceOutId = ifOut,
        SourceAddresses = src,
        DestinationAddresses = dst,
        DestinationPorts = ports,
        ConnectionState = states,
        RateLimit = rate,
        Enabled = enabled
    };

    // ---------------------------------------------------------------------
    // The shapes that must be refused.
    // ---------------------------------------------------------------------

    /// <summary>
    /// The exact row that caused the incident: an accept on all TCP whose only
    /// qualifier is a rate limit. It renders as
    /// `ip protocol tcp limit rate 10/second burst 5 packets accept` and let
    /// the public Internet reach every listening TCP port on a firewall whose
    /// input chain was `policy drop`.
    /// </summary>
    [Fact]
    public void RateLimitedBlanketTcpAccept_IsBypass()
    {
        var reason = FwFilterRuleGuard.DescribeBypass(Rule(rate: "10/second"));

        Assert.NotNull(reason);
        // The operator must be told the rate limit is not the restriction they
        // think it is — that misreading is the whole bug.
        Assert.Contains("rate limit does not narrow it", reason);
        Assert.Contains("10/second", reason);
    }

    [Fact]
    public void BlanketAcceptWithNoProtocol_IsBypass()
    {
        // protocol = null means every protocol: broader still.
        Assert.True(FwFilterRuleGuard.IsDefaultDenyBypass(Rule(protocol: null)));
    }

    [Theory]
    [InlineData("input")]
    [InlineData("forward")]
    public void BothDefaultDenyChains_AreGuarded(string chain)
    {
        Assert.True(FwFilterRuleGuard.IsDefaultDenyBypass(Rule(chain: chain)));
    }

    [Fact]
    public void StateNew_DoesNotNarrow()
    {
        // `ct state new` on an otherwise unrestricted accept still admits every
        // new connection to every port.
        Assert.True(FwFilterRuleGuard.IsDefaultDenyBypass(Rule(states: ["new"])));
    }

    [Fact]
    public void EmptyAndBlankArrays_CountAsAny()
    {
        // The generator treats an empty array exactly like null — no match
        // condition is emitted — so the guard must too.
        Assert.True(FwFilterRuleGuard.IsDefaultDenyBypass(
            Rule(src: [], dst: [], ports: [], states: [])));
        Assert.True(FwFilterRuleGuard.IsDefaultDenyBypass(
            Rule(src: ["  "], ports: [""])));
    }

    [Fact]
    public void MatchingIsCaseInsensitive()
    {
        Assert.True(FwFilterRuleGuard.IsDefaultDenyBypass(
            Rule(chain: "INPUT", action: "Accept", protocol: "TCP")));
    }

    // ---------------------------------------------------------------------
    // The shapes that must keep working. A guard that blocks legitimate rules
    // is worse than no guard — operators would route around it.
    // ---------------------------------------------------------------------

    [Fact]
    public void DisabledRule_IsNeverBypass()
    {
        // A disabled row is not emitted into the ruleset, so it opens nothing.
        // Keeping it storable preserves history; what the guard blocks is
        // turning one back on.
        Assert.Null(FwFilterRuleGuard.DescribeBypass(Rule(rate: "10/second", enabled: false)));
    }

    [Theory]
    [InlineData("drop")]
    [InlineData("reject")]
    [InlineData("log")]
    public void NonAcceptVerdicts_AreNeverBypass(string action)
    {
        // A blanket drop is the default-deny policy, not a hole; log is
        // non-terminal. Only an accept can open the box.
        Assert.Null(FwFilterRuleGuard.DescribeBypass(Rule(action: action)));
    }

    [Fact]
    public void OutputChain_IsNotGuarded()
    {
        // output is `policy accept` by design — a broad accept changes nothing.
        Assert.Null(FwFilterRuleGuard.DescribeBypass(Rule(chain: "output")));
    }

    [Theory]
    [InlineData("icmp")]
    [InlineData("icmpv6")]
    public void RateLimitedIcmpAccept_IsAllowed(string protocol)
    {
        // ICMP has no ports to narrow by, so "allow ping, rate-limited" can
        // only ever be written in the shape the guard would otherwise reject.
        Assert.Null(FwFilterRuleGuard.DescribeBypass(Rule(protocol: protocol, rate: "1/second")));
    }

    [Fact]
    public void EstablishedRelatedAccept_IsAllowed()
    {
        // The standard stateful rule: readmits return traffic for connections
        // this box already allowed out. Not a way in.
        Assert.Null(FwFilterRuleGuard.DescribeBypass(
            Rule(protocol: null, states: ["established", "related"])));
    }

    [Fact]
    public void AnySingleNarrowingCondition_IsEnough()
    {
        var iface = Guid.NewGuid();

        Assert.Null(FwFilterRuleGuard.DescribeBypass(Rule(ifIn: iface)));
        Assert.Null(FwFilterRuleGuard.DescribeBypass(Rule(ifOut: iface)));
        Assert.Null(FwFilterRuleGuard.DescribeBypass(Rule(src: ["192.168.99.0/24"])));
        Assert.Null(FwFilterRuleGuard.DescribeBypass(Rule(dst: ["192.168.99.6"])));
        Assert.Null(FwFilterRuleGuard.DescribeBypass(Rule(ports: ["10000"])));
    }

    /// <summary>
    /// The rules this firewall actually runs must all survive the guard —
    /// otherwise it would refuse the operator's own working ruleset.
    /// </summary>
    [Fact]
    public void RealWorldRuleset_IsNotFlagged()
    {
        var lan = Guid.NewGuid();
        var wan = Guid.NewGuid();

        FwFilterRule[] live =
        [
            Rule(protocol: null, states: ["established", "related"]),          // stateful accept
            Rule(protocol: "udp", ifIn: lan, ports: ["67", "68"]),             // DHCP on LAN
            Rule(protocol: "icmp", rate: "1/second"),                          // rate-limited ping
            Rule(protocol: "tcp", ifIn: lan, ports: ["22"]),                   // SSH from LAN
            Rule(protocol: "tcp", ifIn: wan, src: ["209.126.85.218"], ports: ["22"]), // SSH allowlist
            Rule(protocol: "tcp", ports: ["80", "443"], states: ["new"], rate: "60/minute"),
            Rule(chain: "forward", protocol: null, ifIn: lan),                 // LAN → WAN
            Rule(chain: "forward", action: "drop", protocol: null),            // default drop+log
        ];

        Assert.All(live, r => Assert.Null(FwFilterRuleGuard.DescribeBypass(r)));
    }

    [Fact]
    public void NullRule_IsHandled()
    {
        Assert.Null(FwFilterRuleGuard.DescribeBypass(null));
    }
}
