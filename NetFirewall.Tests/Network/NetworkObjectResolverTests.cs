using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Network;
using NetFirewall.Services.Network;
using NetFirewall.Services.Settings;
using Xunit;

namespace NetFirewall.Tests.Network;

public class NetworkObjectResolverTests
{
    private readonly Mock<INetworkObjectService> _objects = new();
    private readonly Mock<IAppSettingsService> _settings = new();

    private NetworkObjectResolver CreateResolver() =>
        new(_objects.Object, _settings.Object, NullLogger<NetworkObjectResolver>.Instance);

    private static NetworkObject Host(string name, string value)
        => new() { Id = Guid.NewGuid(), Name = name, Type = NetworkObjectTypes.Host, Value = value };

    private static NetworkObject Network(string name, string cidr)
        => new() { Id = Guid.NewGuid(), Name = name, Type = NetworkObjectTypes.Network, Value = cidr };

    private static NetworkObject Range(string name, string range)
        => new() { Id = Guid.NewGuid(), Name = name, Type = NetworkObjectTypes.Range, Value = range };

    private static NetworkObject Group(string name, params NetworkObject[] members)
        => new() { Id = Guid.NewGuid(), Name = name, Type = NetworkObjectTypes.Group, Value = "", Members = members.ToList() };

    private static NetworkObject Fqdn(string name, string host)
        => new() { Id = Guid.NewGuid(), Name = name, Type = NetworkObjectTypes.Fqdn, Value = host };

    private void StubCatalog(params NetworkObject[] all)
        => _objects
            .Setup(s => s.GetAllAsync(It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(all);

    // ── literals ───────────────────────────────────────────────────────

    [Theory]
    [InlineData("10.0.0.5",       "10.0.0.5/32")]
    [InlineData("10.0.0.0/24",    "10.0.0.0/24")]
    [InlineData("10.0.0.5-10.0.0.20", "10.0.0.5-10.0.0.20")]
    public async Task Resolve_PassesLiteralsThrough_AndAddsSlash32ToBareIPs(string input, string expected)
    {
        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(new[] { input });

        Assert.Equal(new[] { expected }, result);
        _objects.Verify(s => s.GetAllAsync(It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task Resolve_IgnoresEmptyAndNullInputs()
    {
        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(new[] { "", "   ", null! });
        Assert.Empty(result);
    }

    [Fact]
    public async Task Resolve_HandlesNullEnumerable()
    {
        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(null!);
        Assert.Empty(result);
    }

    // ── named lookups ──────────────────────────────────────────────────

    [Fact]
    public async Task Resolve_ExpandsHostObject_AddingSlash32()
    {
        StubCatalog(Host("Workstation", "10.0.0.5"));
        var result = await CreateResolver().ResolveAsync(new[] { "Workstation" });
        Assert.Equal(new[] { "10.0.0.5/32" }, result);
    }

    [Fact]
    public async Task Resolve_ExpandsNetworkObject_PreservingCidr()
    {
        StubCatalog(Network("LAN", "192.168.1.0/24"));
        var result = await CreateResolver().ResolveAsync(new[] { "LAN" });
        Assert.Equal(new[] { "192.168.1.0/24" }, result);
    }

    [Fact]
    public async Task Resolve_ExpandsRangeObject_AsRangeLiteral()
    {
        StubCatalog(Range("DhcpPool", "192.168.1.100-192.168.1.200"));
        var result = await CreateResolver().ResolveAsync(new[] { "DhcpPool" });
        Assert.Equal(new[] { "192.168.1.100-192.168.1.200" }, result);
    }

    [Fact]
    public async Task Resolve_LooksUpNamesCaseInsensitively()
    {
        StubCatalog(Host("Server", "1.2.3.4"));
        var result = await CreateResolver().ResolveAsync(new[] { "SERVER", "server" });
        Assert.Equal(new[] { "1.2.3.4/32" }, result); // also dedups
    }

    [Fact]
    public async Task Resolve_SkipsUnknownReferences()
    {
        StubCatalog(Host("Known", "1.2.3.4"));
        var result = await CreateResolver().ResolveAsync(new[] { "Known", "Unknown" });
        Assert.Equal(new[] { "1.2.3.4/32" }, result);
    }

    [Fact]
    public async Task Resolve_DeduplicatesIdenticalLiterals()
    {
        var resolver = CreateResolver();
        var result = await resolver.ResolveAsync(new[] { "10.0.0.5", "10.0.0.5", "10.0.0.5/32" });
        Assert.Equal(new[] { "10.0.0.5/32" }, result);
    }

    [Fact]
    public async Task Resolve_PreservesFirstSeenOrder()
    {
        StubCatalog(Host("A", "10.0.0.1"), Host("B", "10.0.0.2"));
        var result = await CreateResolver().ResolveAsync(new[] { "B", "A", "B" });
        Assert.Equal(new[] { "10.0.0.2/32", "10.0.0.1/32" }, result);
    }

    // ── groups & recursion ─────────────────────────────────────────────

    [Fact]
    public async Task Resolve_ExpandsGroupMembers()
    {
        var server = Host("Web", "10.0.0.10");
        var lan = Network("LAN", "192.168.1.0/24");
        var grp = Group("Trusted", server, lan);
        StubCatalog(server, lan, grp);

        var result = await CreateResolver().ResolveAsync(new[] { "Trusted" });

        Assert.Equal(new[] { "10.0.0.10/32", "192.168.1.0/24" }, result);
    }

    [Fact]
    public async Task Resolve_ExpandsNestedGroups()
    {
        var leaf = Host("DNS", "8.8.8.8");
        var inner = Group("Public", leaf);
        var outer = Group("All", inner);
        StubCatalog(leaf, inner, outer);

        var result = await CreateResolver().ResolveAsync(new[] { "All" });

        Assert.Equal(new[] { "8.8.8.8/32" }, result);
    }

    [Fact]
    public async Task Resolve_StopsAtCycleAndDoesNotInfiniteLoop()
    {
        // Build a -> b -> a directly (must share Members lists, since cycle
        // detection is per-Id).
        var a = new NetworkObject { Id = Guid.NewGuid(), Name = "A", Type = NetworkObjectTypes.Group, Value = "" };
        var b = new NetworkObject { Id = Guid.NewGuid(), Name = "B", Type = NetworkObjectTypes.Group, Value = "" };
        var leaf = Host("X", "1.2.3.4");
        a.Members = new List<NetworkObject> { b, leaf };
        b.Members = new List<NetworkObject> { a }; // cycle!
        StubCatalog(a, b, leaf);

        var result = await CreateResolver().ResolveAsync(new[] { "A" });

        Assert.Equal(new[] { "1.2.3.4/32" }, result); // visited-set prevents infinite recursion
    }

    [Fact]
    public async Task Resolve_LiteralsAndNamesCanMixInOneCall()
    {
        StubCatalog(Host("Server", "10.0.0.5"));
        var resolver = CreateResolver();

        var result = await resolver.ResolveAsync(new[] { "192.168.1.0/24", "Server", "8.8.8.8" });

        Assert.Equal(new[] { "192.168.1.0/24", "10.0.0.5/32", "8.8.8.8/32" }, result);
    }

    [Fact]
    public async Task Resolve_FetchesCatalogOnlyOncePerCall()
    {
        StubCatalog(Host("A", "10.0.0.1"), Host("B", "10.0.0.2"));
        var resolver = CreateResolver();

        await resolver.ResolveAsync(new[] { "A", "B", "A", "B" });

        _objects.Verify(s => s.GetAllAsync(It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ── FQDN ────────────────────────────────────────────────────────────
    // The DNS-success branch hits the static System.Net.Dns class and isn't
    // mockable without refactor. We cover the failure path: when DNS fails
    // and there's no cached entry, the resolver should swallow the error
    // and emit no CIDRs (so the rule is skipped, not fataled).

    [Fact]
    public async Task Resolve_FqdnThatFailsDns_ReturnsEmpty_AndDoesNotThrow()
    {
        // Use an invalid hostname format guaranteed to fail resolution
        // (control char in label) — Dns.GetHostAddressesAsync throws,
        // resolver catches, logs, and emits nothing.
        StubCatalog(Fqdn("Bad", "this.is.nota.host"));
        _settings
            .Setup(s => s.GetIntAsync("network_objects.fqdn_ttl_seconds", It.IsAny<CancellationToken>()))
            .ReturnsAsync(60);

        var result = await CreateResolver().ResolveAsync(new[] { "Bad" });

        Assert.Empty(result);
    }

    [Fact]
    public async Task Resolve_FqdnReadsTtlFromSettings()
    {
        StubCatalog(Fqdn("Bad", "this.is.nota.host"));
        _settings
            .Setup(s => s.GetIntAsync("network_objects.fqdn_ttl_seconds", It.IsAny<CancellationToken>()))
            .ReturnsAsync(600);

        await CreateResolver().ResolveAsync(new[] { "Bad" });

        _settings.Verify(
            s => s.GetIntAsync("network_objects.fqdn_ttl_seconds", It.IsAny<CancellationToken>()),
            Times.Once);
    }
}
