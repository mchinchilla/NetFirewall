using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>Custom options, every class match type, pool allow/deny — all were saved by the UI and ignored.</summary>
public sealed class DhcpOptionsAndClassesTests
{
    // ── Encoder ──

    [Theory]
    [InlineData(150, "ip_list", "10.0.0.5, 10.0.0.6", "0a0000050a000006")]
    [InlineData(66, "string", "tftp.example.com", "746674702e6578616d706c652e636f6d")]
    [InlineData(43, "hex", "06 01 08 ff", "060108ff")]
    [InlineData(23, "uint8", "64", "40")]
    [InlineData(26, "uint16", "1500", "05dc")]
    [InlineData(2, "uint32", "3600", "00000e10")]
    [InlineData(19, "bool", "yes", "01")]
    public void Encoder_EncodesEachFormat(int code, string format, string text, string hex)
    {
        Assert.True(DhcpOptionEncoder.TryEncode(code, format, text, out var data, out var error), error);
        Assert.Equal(hex, Convert.ToHexString(data).ToLowerInvariant());
        Assert.Equal(data, DhcpOptionEncoder.TryEncode(code, format, DhcpOptionEncoder.Decode(format, data), out var again, out _) ? again : null);
    }

    [Theory]
    [InlineData(53, "uint8", "5")]          // message type: protocol-owned
    [InlineData(54, "ip", "10.0.0.1")]      // server identifier
    [InlineData(82, "hex", "01")]           // relay info
    [InlineData(150, "ip_list", "10.0.0")]  // not an address
    [InlineData(23, "uint8", "300")]        // out of range
    [InlineData(43, "hex", "abc")]          // odd hex
    [InlineData(255, "hex", "00")]          // End
    public void Encoder_RefusesBadInput(int code, string format, string text) =>
        Assert.False(DhcpOptionEncoder.TryEncode(code, format, text, out _, out _));

    // ── Class matcher: all eight types ──

    private static DhcpRequest Client() => new()
    {
        ClientMac = "00:0c:29:3e:5c:1a", HType = 1, Hostname = "SEP001122334455",
        VendorClassIdentifier = "Cisco Systems, Inc. IP Phone CP-8841", UserClass = "iPXE",
        ClientIdentifier = [1, 0x00, 0x0C, 0x29, 0x3E, 0x5C, 0x1A],
        RelayAgentInformation = [1, 6, (byte)'G', (byte)'i', (byte)'0', (byte)'/', (byte)'1', (byte)'4'],
        ClientArchitecture = 7,
    };

    [Theory]
    [InlineData("vendor_class", "IP Phone", true)]
    [InlineData("user_class", "ipxe", true)]
    [InlineData("hostname", "SEP00", true)]
    [InlineData("mac_prefix", "00:0C:29", true)]
    [InlineData("mac_prefix", "00-0c-2a", false)]
    [InlineData("hardware_type", "1", true)]
    [InlineData("client_id", "01000c29", true)]
    [InlineData("relay_agent", "Gi0/14", true)]       // circuit-id as text
    [InlineData("relay_agent", "0106", true)]         // or as hex
    [InlineData("option", "60=CP-8841", true)]
    [InlineData("option", "93=7", true)]
    [InlineData("option", "93=0", false)]
    public void ClassMatcher_EveryMatchType(string type, string value, bool expected) =>
        Assert.Equal(expected, DhcpClassMatcher.Matches(Client(), new DhcpClass { MatchType = type, MatchValue = value }));

    // ── Emission: precedence, no overrides of server-set options ──

    private static DhcpCustomOption Opt(short code, string hexValue) => new() { OptionCode = code, OptionValue = Convert.FromHexString(hexValue) };

    private static byte[]? Option(DhcpResponseBuffer r, byte code)
    {
        var s = r.Span;
        for (var i = 240; i < s.Length - 1;)
        {
            if (s[i] == 255) break;
            if (s[i] == 0) { i++; continue; }
            if (s[i] == code) return s.Slice(i + 2, s[i + 1]).ToArray();
            i += 2 + s[i + 1];
        }
        return null;
    }

    [Fact]
    public async Task CustomOptions_HostBeatsClassBeatsSubnet_AndNeverOverrideTheRouterOrDns()
    {
        const string mac = "aa:bb:cc:00:00:01";
        var cls = new DhcpClass { Id = Guid.NewGuid(), Name = "phones", CustomOptions = [Opt(66, "aa"), Opt(150, "0a000005")] };
        var subnet = new DhcpSubnet
        {
            Id = Guid.NewGuid(), Name = "LAN", Network = "192.168.50.0/24", SubnetMask = IPAddress.Parse("255.255.255.0"),
            Router = IPAddress.Parse("192.168.50.1"), DnsServers = [IPAddress.Parse("192.168.50.1")], DefaultLeaseTime = 3600,
            CustomOptions = [Opt(66, "bb"), Opt(252, "cc"), Opt(3, "01020304"), Opt(6, "08080808")],
            HostOptions = new Dictionary<string, IReadOnlyList<DhcpCustomOption>>(StringComparer.OrdinalIgnoreCase)
                { [mac] = [Opt(66, "dd")] },
        };
        var subnets = new Mock<IDhcpSubnetService>();
        subnets.Setup(x => x.FindSubnetForRequestAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>())).ReturnsAsync(subnet);
        subnets.Setup(x => x.MatchClientClassAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>())).ReturnsAsync(cls);
        subnets.Setup(x => x.FindAvailableIpInSubnetAsync(subnet, mac, It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>()))
               .ReturnsAsync((IPAddress.Parse("192.168.50.120"), null));
        var svc = new DhcpServerService(new Mock<IDhcpLeasesService>().Object, subnets.Object,
            NullLogger<DhcpServerService>.Instance, Options.Create(new DhcpConfig()));

        using var r = await svc.CreateDhcpResponseAsync(new DhcpRequest
        {
            ClientMac = mac, ChAddr = new byte[16], Xid = [1, 2, 3, 4], MessageType = DhcpMessageType.Discover,
            CiAddr = IPAddress.Any, YiAddr = IPAddress.Any, SiAddr = IPAddress.Any, GiAddr = IPAddress.Any,
        });

        Assert.Equal([0xDD], Option(r, 66));                         // host wins
        Assert.Equal([0x0A, 0, 0, 5], Option(r, 150));               // from the class
        Assert.Equal([0xCC], Option(r, 252));                        // from the subnet
        Assert.Equal(IPAddress.Parse("192.168.50.1").GetAddressBytes(), Option(r, 3));   // server's router stands
        Assert.Equal(IPAddress.Parse("192.168.50.1").GetAddressBytes(), Option(r, 6));   // server's DNS stands
    }
}

/// <summary>Real Postgres: custom options persisted, loaded into the server cache; pool class rules enforced.</summary>
[Collection("Postgres")]
public sealed class DhcpOptionsPersistenceTests(PostgresFixture pg) : IAsyncLifetime
{
    private DhcpSubnetService _subnets = null!;
    private DhcpCustomOptionService _options = null!;
    private DhcpSubnet _subnet = null!;

    public async Task InitializeAsync()
    {
        await pg.ResetSchemaAsync();
        await pg.BootstrapApplicationSchemaAsync();
        _subnets = new DhcpSubnetService(pg.DataSource, NullLogger<DhcpSubnetService>.Instance);
        _options = new DhcpCustomOptionService(pg.DataSource, new Mock<IDhcpCacheNotifier>().Object, NullLogger<DhcpCustomOptionService>.Instance);
        _subnet = await _subnets.CreateSubnetAsync(new DhcpSubnet
        {
            Name = "home", Network = "10.91.0.0/24", SubnetMask = IPAddress.Parse("255.255.255.0"), Router = IPAddress.Parse("10.91.0.1"), Enabled = true,
        });
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private async Task Exec(string sql)
    {
        await using var c = await pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(sql, c);
        await cmd.ExecuteNonQueryAsync();
    }

    [Fact]
    public async Task SavedOptions_ReachTheCachedSubnet_SubnetOverridingGlobal_AndSaveUpserts()
    {
        Assert.True((await _options.SaveAsync(new(null, "global", null, 42, "NTP", "ip_list", "1.1.1.1"))).Success);
        Assert.True((await _options.SaveAsync(new(null, "subnet", _subnet.Id, 42, "NTP", "ip_list", "10.91.0.1"))).Success);
        Assert.True((await _options.SaveAsync(new(null, "global", null, 252, null, "string", "http://wpad/x"))).Success);
        var again = await _options.SaveAsync(new(null, "global", null, 252, null, "string", "http://wpad/y"));   // same scope+code → update

        Assert.True(again.Success);
        Assert.Equal(3, (await _options.ListAsync()).Count);
        _subnets.InvalidateCache();
        var cached = (await _subnets.GetAllSubnetsAsync()).Single();
        Assert.Equal([10, 91, 0, 1], cached.CustomOptions.Single(o => o.OptionCode == 42).OptionValue);
        Assert.Equal("http://wpad/y"u8.ToArray(), cached.CustomOptions.Single(o => o.OptionCode == 252).OptionValue);
    }

    [Fact]
    public async Task Save_RefusesProtocolOwnedCodes_AndMissingScopes()
    {
        Assert.False((await _options.SaveAsync(new(null, "global", null, 54, null, "ip", "10.0.0.1"))).Success);
        Assert.False((await _options.SaveAsync(new(null, "subnet", null, 66, null, "string", "x"))).Success);
        Assert.False((await _options.SaveAsync(new(null, "class", Guid.NewGuid(), 66, null, "string", "x"))).Success);
    }

    [Fact]
    public async Task PoolClassRules_AllowListAndDeny_AreEnforced()
    {
        var pool = await _subnets.CreatePoolAsync(new DhcpPool { SubnetId = _subnet.Id, Name = "phones", RangeStart = IPAddress.Parse("10.91.0.100"), RangeEnd = IPAddress.Parse("10.91.0.110"), Enabled = true });
        var phones = Guid.NewGuid(); var cameras = Guid.NewGuid();
        await Exec($"INSERT INTO dhcp_classes (id, name, match_type, match_value) VALUES ('{phones}', 'phones', 'vendor_class', 'Phone'), ('{cameras}', 'cameras', 'vendor_class', 'Cam')");
        await Exec($"INSERT INTO dhcp_pool_classes (pool_id, class_id, allow) VALUES ('{pool.Id}', '{phones}', true)");
        _subnets.InvalidateCache();
        await _subnets.GetAllSubnetsAsync();   // reload (rules included)
        var req = new DhcpRequest { ClientMac = "aa:bb:cc:00:00:01" };

        Assert.True(_subnets.IsClientAllowedInPool(pool, req, new DhcpClass { Id = phones }, isKnown: false));
        Assert.False(_subnets.IsClientAllowedInPool(pool, req, new DhcpClass { Id = cameras }, isKnown: false));   // not on the allow-list
        Assert.False(_subnets.IsClientAllowedInPool(pool, req, null, isKnown: false));                              // no class at all

        await Exec($"DELETE FROM dhcp_pool_classes; INSERT INTO dhcp_pool_classes (pool_id, class_id, allow) VALUES ('{pool.Id}', '{cameras}', false)");
        _subnets.InvalidateCache();
        await _subnets.GetAllSubnetsAsync();
        Assert.False(_subnets.IsClientAllowedInPool(pool, req, new DhcpClass { Id = cameras }, isKnown: false));   // denied
        Assert.True(_subnets.IsClientAllowedInPool(pool, req, null, isKnown: false));                               // everyone else

        pool.KnownClientsOnly = true;
        Assert.False(_subnets.IsClientAllowedInPool(pool, req, null, isKnown: false));
        Assert.True(_subnets.IsClientAllowedInPool(pool, req, null, isKnown: true));
    }
}
