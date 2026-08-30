using NetFirewall.Models.Firewall;
using Xunit;

namespace NetFirewall.Tests.Firewall;

/// <summary>
/// Coverage for <see cref="FwRuleShadowAnalyzer"/> — "this rule can never run
/// because an earlier one in the same chain already matches everything it
/// matches".
///
/// The bar is deliberately asymmetric: a missed shadow costs nothing, a false
/// one teaches the operator to ignore the warning. Most of these tests are
/// therefore about NOT reporting.
/// </summary>
public class FwRuleShadowAnalyzerTests
{
    private static FwFilterRule Rule(
        int priority,
        string action = "accept",
        string? protocol = null,
        string[]? ports = null,
        string[]? src = null,
        string[]? states = null,
        Guid? ifIn = null,
        string? rate = null,
        Guid? schedule = null,
        bool enabled = true,
        string? description = null) => new()
    {
        Id = Guid.NewGuid(),
        Chain = "input",
        Priority = priority,
        Action = action,
        Protocol = protocol,
        DestinationPorts = ports,
        SourceAddresses = src,
        ConnectionState = states,
        InterfaceInId = ifIn,
        RateLimit = rate,
        ScheduleId = schedule,
        Enabled = enabled,
        Description = description
    };

    /// <summary>
    /// The real case. A bare `accept` on all TCP at priority 60 turned the
    /// port-scan drops and the catch-all below it into dead code.
    /// </summary>
    [Fact]
    public void BlanketAccept_ShadowsEveryNarrowerRuleBelowIt()
    {
        var blanket = Rule(60, "accept", protocol: "tcp", description: "SYN flood rate-limited");
        var scanDrop = Rule(70, "drop", protocol: "tcp", ports: ["135", "139", "445"]);
        var sshAccept = Rule(100, "accept", protocol: "tcp", ports: ["22"], states: ["new"]);

        var shadowed = FwRuleShadowAnalyzer.FindShadowed([blanket, scanDrop, sshAccept]);

        Assert.Equal(blanket.Id, shadowed[scanDrop.Id].Id);
        Assert.Equal(blanket.Id, shadowed[sshAccept.Id].Id);
        Assert.False(shadowed.ContainsKey(blanket.Id));
    }

    [Fact]
    public void RulesAboveTheBlanket_AreUntouched()
    {
        var sshFromLan = Rule(30, "accept", protocol: "tcp", ports: ["22"]);
        var blanket = Rule(60, "accept", protocol: "tcp");

        var shadowed = FwRuleShadowAnalyzer.FindShadowed([sshFromLan, blanket]);

        Assert.Empty(shadowed);
    }

    [Fact]
    public void FirstShadowingRule_IsTheOneReported()
    {
        // Two broad rules could both hide it; naming the earliest is what tells
        // the operator where to actually fix the ruleset.
        var first = Rule(10, "accept", description: "first");
        var second = Rule(20, "accept", description: "second");
        var victim = Rule(30, "accept", protocol: "tcp", ports: ["22"]);

        var shadowed = FwRuleShadowAnalyzer.FindShadowed([first, second, victim]);

        Assert.Equal(first.Id, shadowed[victim.Id].Id);
    }

    // ── must NOT report ────────────────────────────────────────────────

    [Fact]
    public void RateLimitedRule_ShadowsNothing()
    {
        // Above the limit the rule stops matching and traffic falls through, so
        // everything below it is reachable.
        var limited = Rule(50, "accept", protocol: "tcp", rate: "10/second");
        var below = Rule(60, "drop", protocol: "tcp", ports: ["445"]);

        Assert.Empty(FwRuleShadowAnalyzer.FindShadowed([limited, below]));
    }

    [Fact]
    public void ScheduledRule_ShadowsNothing()
    {
        // Outside its window the rules below run normally.
        var scheduled = Rule(50, "accept", schedule: Guid.NewGuid());
        var below = Rule(60, "drop", protocol: "tcp", ports: ["445"]);

        Assert.Empty(FwRuleShadowAnalyzer.FindShadowed([scheduled, below]));
    }

    [Fact]
    public void LogRule_ShadowsNothing()
    {
        // `log` is non-terminal: evaluation continues past it.
        var log = Rule(50, "log");
        var below = Rule(60, "drop", protocol: "tcp");

        Assert.Empty(FwRuleShadowAnalyzer.FindShadowed([log, below]));
    }

    [Fact]
    public void DisabledRules_NeitherShadowNorAreShadowed()
    {
        // A disabled rule is not written into the ruleset at all.
        var disabledBlanket = Rule(50, "accept", enabled: false);
        var below = Rule(60, "drop", protocol: "tcp", ports: ["445"]);
        var disabledBelow = Rule(70, "drop", protocol: "tcp", enabled: false);
        var blanket = Rule(55, "accept");

        var shadowed = FwRuleShadowAnalyzer.FindShadowed([disabledBlanket, blanket, below, disabledBelow]);

        Assert.True(shadowed.ContainsKey(below.Id));          // hidden by the ENABLED blanket
        Assert.Equal(blanket.Id, shadowed[below.Id].Id);
        Assert.False(shadowed.ContainsKey(disabledBelow.Id));
    }

    [Fact]
    public void NarrowerInterface_IsNotShadowedByAnotherInterface()
    {
        var onEth0 = Rule(10, "accept", ifIn: Guid.NewGuid());
        var onEth1 = Rule(20, "accept", ifIn: Guid.NewGuid());

        Assert.Empty(FwRuleShadowAnalyzer.FindShadowed([onEth0, onEth1]));
    }

    [Fact]
    public void InterfaceScopedRule_DoesNotShadowAnAnyInterfaceRule()
    {
        // The broad rule is the SECOND one here: an interface-scoped rule can
        // never cover one that applies everywhere.
        var scoped = Rule(10, "accept", ifIn: Guid.NewGuid());
        var anywhere = Rule(20, "accept");

        Assert.Empty(FwRuleShadowAnalyzer.FindShadowed([scoped, anywhere]));
    }

    [Fact]
    public void DifferentProtocol_IsNotShadowed()
    {
        var tcp = Rule(10, "accept", protocol: "tcp");
        var udp = Rule(20, "accept", protocol: "udp", ports: ["53"]);

        Assert.Empty(FwRuleShadowAnalyzer.FindShadowed([tcp, udp]));
    }

    [Fact]
    public void CidrContainment_IsNotInferred()
    {
        // 10.0.0.0/8 does contain 10.1.0.0/16, but proving that from strings is
        // where false positives come from. Stay literal.
        var broad = Rule(10, "accept", src: ["10.0.0.0/8"]);
        var inside = Rule(20, "accept", src: ["10.1.0.0/16"]);

        Assert.Empty(FwRuleShadowAnalyzer.FindShadowed([broad, inside]));
    }

    [Fact]
    public void PortSubset_IsShadowed_WhenListedLiterally()
    {
        var broad = Rule(10, "drop", protocol: "tcp", ports: ["80", "443"]);
        var subset = Rule(20, "drop", protocol: "tcp", ports: ["443"]);

        var shadowed = FwRuleShadowAnalyzer.FindShadowed([broad, subset]);

        Assert.Equal(broad.Id, shadowed[subset.Id].Id);
    }

    [Fact]
    public void StatefulAccept_DoesNotShadowNewConnectionRules()
    {
        // `ct state established,related` is the first rule of every chain here;
        // it must never be reported as hiding the service rules below it.
        var stateful = Rule(3, "accept", states: ["established", "related"]);
        var ssh = Rule(30, "accept", protocol: "tcp", ports: ["22"], states: ["new"]);
        var noState = Rule(40, "accept", protocol: "tcp", ports: ["5432"]);

        Assert.Empty(FwRuleShadowAnalyzer.FindShadowed([stateful, ssh, noState]));
    }

    [Fact]
    public void RealChain_ReportsOnlyWhatTheBlanketHides()
    {
        // The input chain as it stood during the incident, trimmed.
        var invalid = Rule(1, "drop", states: ["invalid"]);
        var established = Rule(3, "accept", states: ["established", "related"]);
        var sshLan = Rule(30, "accept", protocol: "tcp", ports: ["22"], ifIn: Guid.NewGuid());
        var httpLimited = Rule(50, "accept", protocol: "tcp", ports: ["80", "443"], states: ["new"], rate: "60/minute");
        var blanket = Rule(60, "accept", protocol: "tcp", rate: "10/second");
        var synDrop = Rule(61, "drop", protocol: "tcp");
        var scanDrop = Rule(70, "drop", protocol: "tcp", ports: ["135", "139", "445"]);
        var catchAll = Rule(1000, "drop");

        var shadowed = FwRuleShadowAnalyzer.FindShadowed(
            [invalid, established, sshLan, httpLimited, blanket, synDrop, scanDrop, catchAll]);

        // The blanket carries a rate limit, so it is NOT the one flagged —
        // priority 61 is: a bare `drop` on all TCP with nothing narrowing it.
        Assert.False(shadowed.ContainsKey(blanket.Id));
        Assert.Equal(synDrop.Id, shadowed[scanDrop.Id].Id);
        Assert.False(shadowed.ContainsKey(catchAll.Id)); // tcp-only can't cover "any"
    }

    [Fact]
    public void NullInput_IsHandled()
    {
        Assert.Empty(FwRuleShadowAnalyzer.FindShadowed(null));
    }
}
