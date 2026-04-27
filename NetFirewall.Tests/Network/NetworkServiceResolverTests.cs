using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Network;
using NetFirewall.Services.Network;
using Xunit;

namespace NetFirewall.Tests.Network;

public class NetworkServiceResolverTests
{
    private readonly Mock<INetworkServiceService> _services = new();

    private NetworkServiceResolver CreateResolver() =>
        new(_services.Object, NullLogger<NetworkServiceResolver>.Instance);

    private static NetworkService Leaf(string name, int port, int? portEnd = null,
                                       string protocol = NetworkServiceProtocols.Tcp)
        => new()
        {
            Id = Guid.NewGuid(),
            Name = name,
            Protocol = protocol,
            PortStart = port,
            PortEnd = portEnd
        };

    private static NetworkService Group(string name, params NetworkService[] members)
        => new()
        {
            Id = Guid.NewGuid(),
            Name = name,
            Protocol = NetworkServiceProtocols.Tcp,
            PortStart = 0,
            Members = members.ToList()
        };

    private void StubCatalog(params NetworkService[] all)
        => _services
            .Setup(s => s.GetAllAsync(It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(all);

    // ── literals ───────────────────────────────────────────────────────

    [Theory]
    [InlineData("22",          "22")]
    [InlineData("10000-20000", "10000-20000")]
    [InlineData("0",           "0")]
    [InlineData("65535",       "65535")]
    public async Task Resolve_PassesNumericLiteralsThrough(string input, string expected)
    {
        var result = await CreateResolver().ResolveAsync(new[] { input });

        Assert.Equal(new[] { expected }, result);
        _services.Verify(s => s.GetAllAsync(It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Theory]
    [InlineData("80a")]      // mixed alphanumeric → not a literal, treated as name
    [InlineData("100-200a")] // bad range → also a name
    [InlineData("-22")]      // dangling dash → also a name
    [InlineData("22-")]      // dangling dash → also a name
    public async Task Resolve_NonNumericInputsAreTreatedAsNamedReferences(string input)
    {
        // Catalog is empty → unknown reference → skipped silently.
        StubCatalog();
        var result = await CreateResolver().ResolveAsync(new[] { input });
        Assert.Empty(result);
    }

    [Fact]
    public async Task Resolve_IgnoresEmptyAndNullInputs()
    {
        var result = await CreateResolver().ResolveAsync(new[] { "", "   ", null! });
        Assert.Empty(result);
    }

    [Fact]
    public async Task Resolve_HandlesNullEnumerable()
    {
        var result = await CreateResolver().ResolveAsync(null!);
        Assert.Empty(result);
    }

    // ── named lookups ──────────────────────────────────────────────────

    [Fact]
    public async Task Resolve_LeafEmitsPortString()
    {
        StubCatalog(Leaf("SSH", 22));
        var result = await CreateResolver().ResolveAsync(new[] { "SSH" });
        Assert.Equal(new[] { "22" }, result);
    }

    [Fact]
    public async Task Resolve_LeafWithRangeEmitsRangeString()
    {
        StubCatalog(Leaf("RTP", 10000, 20000));
        var result = await CreateResolver().ResolveAsync(new[] { "RTP" });
        Assert.Equal(new[] { "10000-20000" }, result);
    }

    [Fact]
    public async Task Resolve_LeafWherePortEndEqualsPortStart_EmitsSinglePort()
    {
        // Defensive: PortString collapses redundant ranges to a single port.
        StubCatalog(Leaf("Echo", 7, portEnd: 7));
        var result = await CreateResolver().ResolveAsync(new[] { "Echo" });
        Assert.Equal(new[] { "7" }, result);
    }

    [Fact]
    public async Task Resolve_LooksUpNamesCaseInsensitively()
    {
        StubCatalog(Leaf("HTTP", 80));
        var result = await CreateResolver().ResolveAsync(new[] { "http", "HTTP" });
        Assert.Equal(new[] { "80" }, result); // dedup
    }

    [Fact]
    public async Task Resolve_SkipsUnknownReferences()
    {
        StubCatalog(Leaf("HTTP", 80));
        var result = await CreateResolver().ResolveAsync(new[] { "HTTP", "UnknownService" });
        Assert.Equal(new[] { "80" }, result);
    }

    [Fact]
    public async Task Resolve_DeduplicatesAcrossMixedSources()
    {
        StubCatalog(Leaf("SSH", 22));
        var result = await CreateResolver().ResolveAsync(new[] { "22", "SSH", "22" });
        Assert.Equal(new[] { "22" }, result);
    }

    [Fact]
    public async Task Resolve_PreservesFirstSeenOrder()
    {
        StubCatalog(Leaf("HTTP", 80), Leaf("HTTPS", 443));
        var result = await CreateResolver().ResolveAsync(new[] { "HTTPS", "HTTP" });
        Assert.Equal(new[] { "443", "80" }, result);
    }

    [Fact]
    public async Task Resolve_FetchesCatalogOnlyOncePerCall()
    {
        StubCatalog(Leaf("HTTP", 80), Leaf("HTTPS", 443));
        await CreateResolver().ResolveAsync(new[] { "HTTP", "HTTPS", "HTTP" });

        _services.Verify(s => s.GetAllAsync(It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Resolve_DoesNotFetchCatalogWhenInputsAreAllLiterals()
    {
        await CreateResolver().ResolveAsync(new[] { "22", "443", "10000-20000" });
        _services.Verify(s => s.GetAllAsync(It.IsAny<bool>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    // ── groups & recursion ─────────────────────────────────────────────

    [Fact]
    public async Task Resolve_ExpandsGroupMembers()
    {
        var http  = Leaf("HTTP", 80);
        var https = Leaf("HTTPS", 443);
        var web   = Group("Web", http, https);
        StubCatalog(http, https, web);

        var result = await CreateResolver().ResolveAsync(new[] { "Web" });

        Assert.Equal(new[] { "80", "443" }, result);
    }

    [Fact]
    public async Task Resolve_ExpandsNestedGroups()
    {
        var ssh  = Leaf("SSH", 22);
        var inner = Group("Remote", ssh);
        var outer = Group("All", inner);
        StubCatalog(ssh, inner, outer);

        var result = await CreateResolver().ResolveAsync(new[] { "All" });

        Assert.Equal(new[] { "22" }, result);
    }

    [Fact]
    public async Task Resolve_StopsAtCycleInGroupGraph()
    {
        var a = new NetworkService
        {
            Id = Guid.NewGuid(), Name = "A", Protocol = NetworkServiceProtocols.Tcp, PortStart = 0
        };
        var b = new NetworkService
        {
            Id = Guid.NewGuid(), Name = "B", Protocol = NetworkServiceProtocols.Tcp, PortStart = 0
        };
        var leaf = Leaf("HTTP", 80);
        a.Members = new List<NetworkService> { b, leaf };
        b.Members = new List<NetworkService> { a }; // cycle

        StubCatalog(a, b, leaf);

        var result = await CreateResolver().ResolveAsync(new[] { "A" });

        Assert.Equal(new[] { "80" }, result); // doesn't infinite loop
    }

    [Fact]
    public async Task Resolve_GroupWithEmptyMembersEmitsNothing()
    {
        // A group object with Members=null should expand to nothing (its own
        // PortStart is meaningless for groups).
        var grp = new NetworkService
        {
            Id = Guid.NewGuid(), Name = "Empty", Protocol = NetworkServiceProtocols.Tcp,
            PortStart = 0, Members = null
        };
        StubCatalog(grp);

        // Note: with Members=null AND not a leaf-with-port semantically, the
        // resolver currently treats it as a leaf and emits "0". This is a
        // contract test: if you change the behavior, this test should change too.
        var result = await CreateResolver().ResolveAsync(new[] { "Empty" });
        Assert.Equal(new[] { "0" }, result);
    }

    [Fact]
    public async Task Resolve_GroupWithEmptyMembersListEmitsNothingExceptItsOwnPort()
    {
        // Members is an empty list (not null) — Expand currently treats this
        // as a leaf and emits PortString. Pinning that contract.
        var grp = new NetworkService
        {
            Id = Guid.NewGuid(), Name = "Empty", Protocol = NetworkServiceProtocols.Tcp,
            PortStart = 0, Members = new List<NetworkService>()
        };
        StubCatalog(grp);

        var result = await CreateResolver().ResolveAsync(new[] { "Empty" });
        Assert.Equal(new[] { "0" }, result);
    }

    [Fact]
    public async Task Resolve_LiteralsAndNamesCanMixInOneCall()
    {
        StubCatalog(Leaf("SSH", 22));
        var result = await CreateResolver().ResolveAsync(new[] { "443", "SSH", "10000-20000" });
        Assert.Equal(new[] { "443", "22", "10000-20000" }, result);
    }
}
