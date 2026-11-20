using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Network;
using NetFirewall.Services.Network;
using NetFirewall.Services.Processes;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Network;

/// <summary>DHCP hostnames in the firewall's resolver: `ping nas.home.lan`.</summary>
public sealed class LocalDnsZoneTests
{
    private static readonly LocalDnsDomain[] Domains = [new("192.168.1.0/24", "home.lan."), new("10.20.0.0/24", null)];

    [Fact]
    public void Render_PublishesAAndPtr_UnderTheSubnetDomain()
    {
        var conf = LocalDnsZone.Render([new("nas", IPAddress.Parse("192.168.1.10"), true)], Domains);
        Assert.Contains("local-zone: \"home.lan.\" transparent", conf);
        Assert.Contains("local-data: \"nas.home.lan. 300 IN A 192.168.1.10\"", conf);
        Assert.Contains("local-data-ptr: \"192.168.1.10 nas.home.lan\"", conf);
    }

    [Fact]
    public void Render_SanitizesClientNames_AndFallsBackToLan()
    {
        var conf = LocalDnsZone.Render([new("Marvin's iPhone", IPAddress.Parse("10.20.0.7"), false)], Domains);
        Assert.Contains("local-data: \"marvins-iphone.lan. 300 IN A 10.20.0.7\"", conf);
    }

    [Fact]
    public void Render_AReservationWinsTheName_OverALease()
    {
        var conf = LocalDnsZone.Render(
        [
            new("printer", IPAddress.Parse("192.168.1.50"), false),   // a lease claiming the name
            new("printer", IPAddress.Parse("192.168.1.9"), true),     // the reservation
        ], Domains);
        Assert.Contains("printer.home.lan. 300 IN A 192.168.1.9", conf);
        Assert.DoesNotContain("192.168.1.50", conf);
    }

    [Fact]
    public void Render_IsDeterministic_SoAnUnchangedTableDoesNotReload()
    {
        LocalDnsHost[] a = [new("b", IPAddress.Parse("192.168.1.2"), false), new("a", IPAddress.Parse("192.168.1.1"), false)];
        Assert.Equal(LocalDnsZone.Render(a, Domains), LocalDnsZone.Render(a.Reverse(), Domains));
    }

    [Theory]
    [InlineData("laptop.corp.example", "laptop")]
    [InlineData("  Living Room TV ", "living-room-tv")]
    [InlineData("___", null)]
    [InlineData("-x-", "x")]
    public void Sanitize(string raw, string? expected) => Assert.Equal(expected, DnsHostName.Sanitize(raw));
}

[Collection("Postgres")]
public sealed class LocalDnsPublisherServiceTests(PostgresFixture pg) : IAsyncLifetime
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), $"unbound-{Guid.NewGuid():N}");
    private readonly Mock<IProcessRunner> _runner = new();

    public async Task InitializeAsync()
    {
        await pg.ResetSchemaAsync();
        await pg.BootstrapApplicationSchemaAsync();
        Directory.CreateDirectory(_dir);
        _runner.Setup(r => r.RunAsync(It.IsAny<string>(), It.IsAny<IReadOnlyList<string>>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
               .ReturnsAsync(new ProcessResult(0, "", ""));
        await using var c = await pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand("""
            INSERT INTO dhcp_mac_reservations (id, mac_address, reserved_ip, hostname) VALUES (uuid_generate_v4(), 'aa:bb:cc:00:00:01', '192.168.1.10', 'nas');
            INSERT INTO dhcp_leases (id, mac_address, ip_address, hostname, start_time, end_time)
                VALUES (uuid_generate_v4(), 'aa:bb:cc:00:00:02', '192.168.1.120', 'laptop', now(), now() + interval '1 hour'),
                       (uuid_generate_v4(), 'aa:bb:cc:00:00:03', '192.168.1.121', 'gone', now() - interval '2 hours', now() - interval '1 hour');
            """, c);
        await cmd.ExecuteNonQueryAsync();
    }

    public Task DisposeAsync() { Directory.Delete(_dir, recursive: true); return Task.CompletedTask; }

    private LocalDnsPublisherService Svc() => new(pg.DataSource, _runner.Object, NullLogger<LocalDnsPublisherService>.Instance, _dir);

    [Fact]
    public async Task WithoutOurForwarder_NothingIsPublished()
    {
        Assert.Equal("inactive", await Svc().PublishOnceAsync(default));
        Assert.False(File.Exists(Path.Combine(_dir, "netfirewall-hosts.conf")));
    }

    [Fact]
    public async Task PublishesActiveNamesOnce_ThenOnlyOnChange()
    {
        await File.WriteAllTextAsync(Path.Combine(_dir, "netfirewall.conf"), "server:\n");
        var svc = Svc();

        Assert.Equal("published", await svc.PublishOnceAsync(default));
        var conf = await File.ReadAllTextAsync(Path.Combine(_dir, "netfirewall-hosts.conf"));
        Assert.Contains("nas.lan. 300 IN A 192.168.1.10", conf);
        Assert.Contains("laptop.lan. 300 IN A 192.168.1.120", conf);
        Assert.DoesNotContain("gone", conf);                                  // expired lease
        Assert.Equal("unchanged", await svc.PublishOnceAsync(default));        // no second reload
        _runner.Verify(r => r.RunAsync("systemctl", It.Is<IReadOnlyList<string>>(a => a.Contains("reload")), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ARejectedFile_IsRolledBack()
    {
        await File.WriteAllTextAsync(Path.Combine(_dir, "netfirewall.conf"), "server:\n");
        _runner.Setup(r => r.RunAsync("unbound-checkconf", It.IsAny<IReadOnlyList<string>>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
               .ReturnsAsync(new ProcessResult(1, "", "syntax error"));

        Assert.Equal("rejected", await Svc().PublishOnceAsync(default));
        Assert.False(File.Exists(Path.Combine(_dir, "netfirewall-hosts.conf")));
        _runner.Verify(r => r.RunAsync("systemctl", It.IsAny<IReadOnlyList<string>>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}
