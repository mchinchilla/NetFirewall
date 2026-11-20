using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// The packet builder emits option 2 (time offset) and option 100 (POSIX TZ) from the
/// CACHED subnet, as do options 119 (domain search) and 121 (classless static routes); the cache
/// SELECT used to leave all four columns out, so none of them was ever sent.
/// </summary>
[Collection("Postgres")]
public sealed class DhcpSubnetCacheOptionsTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private DhcpSubnetService _svc = null!;
    private LeaseCache _leaseCache = null!;

    public DhcpSubnetCacheOptionsTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _leaseCache = new LeaseCache(_pg.DataSource, NullLogger<LeaseCache>.Instance,
            batchSize: 100, batchIntervalMs: 20, cleanupIntervalSeconds: 60);
        _svc = new DhcpSubnetService(_pg.DataSource, NullLogger<DhcpSubnetService>.Instance, _leaseCache);
    }

    public Task DisposeAsync()
    {
        _leaseCache.Dispose();
        return Task.CompletedTask;
    }

    [Fact]
    public async Task CachedSubnet_CarriesTimeOffsetAndPosixTimezone()
    {
        var created = await _svc.CreateSubnetAsync(new DhcpSubnet
        {
            Name = "tz-lan",
            Network = "10.70.0.0/24",
            SubnetMask = IPAddress.Parse("255.255.255.0"),
            Router = IPAddress.Parse("10.70.0.1"),
            Enabled = true,
        });

        await using (var conn = await _pg.DataSource.OpenConnectionAsync())
        await using (var cmd = new NpgsqlCommand(
            "UPDATE dhcp_subnets SET time_offset = -21600, posix_timezone = 'CST6', domain_search = 'corp.example lab.example', static_routes = '[{\"network\":\"10.80.0.0/16\",\"gateway\":\"10.70.0.254\"}]'::jsonb WHERE id = @id", conn))
        {
            cmd.Parameters.AddWithValue("id", created.Id);
            await cmd.ExecuteNonQueryAsync();
        }
        _svc.InvalidateCache();

        var cached = Assert.Single(await _svc.GetAllSubnetsAsync());
        Assert.Equal(-21600, cached.TimeOffset);
        Assert.Equal("CST6", cached.PosixTimezone);
        Assert.Equal("corp.example lab.example", cached.DomainSearchList);
        Assert.Contains("10.80.0.0/16", cached.StaticRoutesJson);
        // jsonb comes back re-formatted; it must still encode to a non-empty RFC 3442 option.
        Assert.NotEmpty(DhcpOptionExtensions.EncodeClasslessStaticRoutes(cached.StaticRoutesJson));
        Assert.NotEmpty(DhcpOptionExtensions.EncodeDomainSearchList(cached.DomainSearchList));
    }
}
