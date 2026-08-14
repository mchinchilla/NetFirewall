using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Services.Dhcp;
using NetFirewall.Tests.Infra;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Regression coverage for the LeaseCache dual-index races: removals from
/// <c>_byIp</c>/<c>_byMac</c> must be conditional on the exact entry observed —
/// a blind key removal could evict ANOTHER client's fresh lease, making its IP
/// look free and double-offerable.
/// </summary>
[Collection("Postgres")]
public sealed class LeaseCacheRaceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private LeaseCache _cache = null!;

    public LeaseCacheRaceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _cache = new LeaseCache(_pg.DataSource, NullLogger<LeaseCache>.Instance,
            batchSize: 100, batchIntervalMs: 20, cleanupIntervalSeconds: 3600);
    }

    public Task DisposeAsync()
    {
        _cache.Dispose();
        return Task.CompletedTask;
    }

    private static readonly IPAddress IpX = IPAddress.Parse("10.50.0.10");
    private static readonly IPAddress IpY = IPAddress.Parse("10.50.0.20");
    private const string MacA = "aa:aa:aa:00:00:01";
    private const string MacB = "bb:bb:bb:00:00:02";

    [Fact]
    public async Task MacMovesToNewIp_DoesNotEvictNewOwnerOfOldIp()
    {
        // A holds X. B takes over X (A's entry in _byIp[X] is displaced).
        // When A then moves to Y, the cleanup of A's "old IP" must NOT remove
        // B's fresh entry from the reverse index — pre-fix it did, and X
        // looked free while B was using it.
        await _cache.SetLeaseAsync(MacA, IpX, 3600);
        await _cache.SetLeaseAsync(MacB, IpX, 3600);
        await _cache.SetLeaseAsync(MacA, IpY, 3600);

        var holderOfX = _cache.GetByIp(IpX);
        Assert.NotNull(holderOfX);
        Assert.Equal(MacB, holderOfX!.MacAddress);
        Assert.True(_cache.IsIpLeased(IpX));

        var holderOfY = _cache.GetByIp(IpY);
        Assert.Equal(MacA, holderOfY!.MacAddress);
    }

    [Fact]
    public async Task ReleaseByIp_RemovesCurrentHolderOnly()
    {
        // B currently holds X (displaced A's reverse-index slot). Releasing X
        // removes B — and must not touch A's active lease on Y.
        await _cache.SetLeaseAsync(MacA, IpX, 3600);
        await _cache.SetLeaseAsync(MacA, IpY, 3600);   // A moved on to Y
        await _cache.SetLeaseAsync(MacB, IpX, 3600);   // B took X

        await _cache.ReleaseLeaseByIpAsync(IpX);

        Assert.Null(_cache.GetByIp(IpX));
        Assert.Null(_cache.GetByMac(MacB));
        // A's lease on Y untouched
        Assert.Equal(IpY, _cache.GetByMac(MacA)!.IpAddress);
    }

    [Fact]
    public async Task ReleaseByMac_LeavesUnrelatedIpMappingsAlone()
    {
        await _cache.SetLeaseAsync(MacA, IpX, 3600);
        await _cache.SetLeaseAsync(MacB, IpY, 3600);

        await _cache.ReleaseLeaseAsync(MacA);

        Assert.Null(_cache.GetByMac(MacA));
        Assert.Null(_cache.GetByIp(IpX));
        Assert.Equal(MacB, _cache.GetByIp(IpY)!.MacAddress);
    }

    [Fact]
    public async Task FindAvailableIp_ExcludesReservedSet()
    {
        // The exclusions parameter is how reservation awareness reaches the
        // allocator — pin that an excluded head-of-range is skipped.
        await _cache.SetLeaseAsync(MacA, IPAddress.Parse("10.50.1.11"), 3600);

        var found = _cache.FindAvailableIp(
            IPAddress.Parse("10.50.1.10"), IPAddress.Parse("10.50.1.20"),
            new HashSet<IPAddress> { IPAddress.Parse("10.50.1.10"), IPAddress.Parse("10.50.1.12") });

        Assert.Equal(IPAddress.Parse("10.50.1.13"), found);
    }

    [Fact]
    public async Task CanMacUseIp_ReflectsCurrentHolder_AfterDisplacement()
    {
        await _cache.SetLeaseAsync(MacA, IpX, 3600);
        await _cache.SetLeaseAsync(MacB, IpX, 3600); // displaces A in _byIp

        Assert.True(_cache.CanMacUseIp(MacB, IpX));
        Assert.False(_cache.CanMacUseIp("cc:cc:cc:00:00:03", IpX));
    }
}
