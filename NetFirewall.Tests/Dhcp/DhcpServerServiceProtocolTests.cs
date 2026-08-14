using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Protocol-conformance coverage for <see cref="DhcpServerService"/> added with
/// the hardening pass: server-identifier gating (RFC 2131 §4.3.2), renewal via
/// ciaddr when option 50 is absent, INFORM semantics (§3.4), and the
/// oversized-option guard that turns corrupt-packet construction into a NAK.
/// </summary>
public class DhcpServerServiceProtocolTests
{
    private readonly Mock<IDhcpLeasesService> _leases = new(MockBehavior.Strict);
    private readonly Mock<IDhcpSubnetService> _subnets = new(MockBehavior.Strict);

    private DhcpServerService CreateSvc() =>
        new(
            _leases.Object,
            _subnets.Object,
            NullLogger<DhcpServerService>.Instance,
            Options.Create(new DhcpConfig
            {
                ServerIp = IPAddress.Parse("10.0.0.1"),
                IpRangeStart = IPAddress.Parse("10.0.0.100"),
                IpRangeEnd = IPAddress.Parse("10.0.0.200"),
                SubnetMask = IPAddress.Parse("255.255.255.0"),
                Gateway = IPAddress.Parse("10.0.0.1"),
                DnsServers = new List<IPAddress> { IPAddress.Parse("8.8.8.8") },
                LeaseTime = 3600
            }));

    private static DhcpRequest MakeRequest(DhcpMessageType type) => new()
    {
        ClientMac = "aa:bb:cc:00:00:01",
        ChAddr = new byte[] { 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        Xid = new byte[] { 1, 2, 3, 4 },
        CiAddr = IPAddress.Any,
        YiAddr = IPAddress.Any,
        SiAddr = IPAddress.Any,
        GiAddr = IPAddress.Any,
        MessageType = type,
        Hostname = "client"
    };

    private void StubSubnetReturning(DhcpSubnet? subnet) =>
        _subnets.Setup(s => s.FindSubnetForRequestAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(subnet);

    private void StubClassMatchNone() =>
        _subnets.Setup(s => s.MatchClientClassAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((DhcpClass?)null);

    private static byte? ExtractMessageType(DhcpResponseBuffer response)
    {
        if (response.IsEmpty) return null;
        var span = response.Span;
        for (var i = 240; i < span.Length - 1; i++)
        {
            if (span[i] == 53 && span[i + 1] == 1)
                return span[i + 2];
            if (span[i] == 0xFF) break;
        }
        return null;
    }

    private static bool HasOption(DhcpResponseBuffer response, byte code)
    {
        var span = response.Span;
        var i = 240;
        while (i < span.Length)
        {
            var c = span[i++];
            if (c == 0xFF) break;
            if (c == 0) continue;
            if (i >= span.Length) break;
            int len = span[i++];
            if (c == code) return true;
            i += len;
        }
        return false;
    }

    // ── Server-identifier gating ───────────────────────────────────────

    [Fact]
    public async Task Request_AddressedToAnotherServer_ReturnsEmpty_NoLeaseCalls()
    {
        // SELECTING client accepted another server's offer (option 54 names
        // it). Answering — even with a NAK — would sabotage the other server's
        // handshake.
        StubSubnetReturning(null);
        StubClassMatchNone();

        var req = MakeRequest(DhcpMessageType.Request);
        req.ServerIdentifier = IPAddress.Parse("10.0.0.99");
        req.RequestedIp = IPAddress.Parse("10.0.0.150");

        using var response = await CreateSvc().CreateDhcpResponseAsync(req);

        Assert.True(response.IsEmpty);
        // Strict mocks: any lease-service call would have thrown already.
    }

    [Fact]
    public async Task Request_AddressedToUs_IsProcessedNormally()
    {
        StubSubnetReturning(null);
        StubClassMatchNone();
        _leases.Setup(l => l.CanAssignIpAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.150")))
            .ReturnsAsync(true);
        _leases.Setup(l => l.AssignLeaseAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.150"), 3600, "client"))
            .Returns(Task.CompletedTask);

        var req = MakeRequest(DhcpMessageType.Request);
        req.ServerIdentifier = IPAddress.Parse("10.0.0.1"); // that's us (fallback ServerIp)
        req.RequestedIp = IPAddress.Parse("10.0.0.150");

        using var response = await CreateSvc().CreateDhcpResponseAsync(req);

        Assert.Equal((byte)DhcpMessageType.Ack, ExtractMessageType(response));
    }

    // ── Renewal without option 50 ──────────────────────────────────────

    [Fact]
    public async Task Request_RenewalWithoutOption50_UsesCiAddr_NotLeaseLookup()
    {
        // RENEWING/REBINDING clients put their address in ciaddr and omit
        // option 50. The old 0.0.0.0 default meant this path never ran and
        // every renewal got CanAssign(0.0.0.0) → NAK.
        StubSubnetReturning(null);
        StubClassMatchNone();
        _leases.Setup(l => l.CanAssignIpAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.150")))
            .ReturnsAsync(true);
        _leases.Setup(l => l.AssignLeaseAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.150"), 3600, "client"))
            .Returns(Task.CompletedTask);

        var req = MakeRequest(DhcpMessageType.Request);
        req.RequestedIp = null;
        req.CiAddr = IPAddress.Parse("10.0.0.150");

        using var response = await CreateSvc().CreateDhcpResponseAsync(req);

        Assert.Equal((byte)DhcpMessageType.Ack, ExtractMessageType(response));
        _leases.Verify(l => l.GetAssignedIpAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task Request_Option50Zero_TreatedAsAbsent_FallsBackToLeaseLookup()
    {
        // A malformed client sending option 50 = 0.0.0.0 must not be NAKed on
        // "requesting the zero address" — treat as absent and look up state.
        StubSubnetReturning(null);
        StubClassMatchNone();
        _leases.Setup(l => l.GetAssignedIpAsync("aa:bb:cc:00:00:01"))
            .ReturnsAsync(IPAddress.Parse("10.0.0.160"));
        _leases.Setup(l => l.CanAssignIpAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.160")))
            .ReturnsAsync(true);
        _leases.Setup(l => l.AssignLeaseAsync("aa:bb:cc:00:00:01", IPAddress.Parse("10.0.0.160"), 3600, "client"))
            .Returns(Task.CompletedTask);

        var req = MakeRequest(DhcpMessageType.Request);
        req.RequestedIp = IPAddress.Any; // parsed from option 50 = 0.0.0.0

        using var response = await CreateSvc().CreateDhcpResponseAsync(req);

        Assert.Equal((byte)DhcpMessageType.Ack, ExtractMessageType(response));
    }

    // ── INFORM semantics ───────────────────────────────────────────────

    [Fact]
    public async Task Inform_AckHasZeroYiaddr_EchoesCiAddr_NoLeaseTime()
    {
        // RFC 2131 §3.4: the INFORM client already has an address (in ciaddr);
        // the ACK must not assign one (yiaddr = 0) and must not carry lease
        // timing options.
        StubSubnetReturning(null);
        StubClassMatchNone();

        var req = MakeRequest(DhcpMessageType.Inform);
        req.CiAddr = IPAddress.Parse("10.0.0.77");

        using var response = await CreateSvc().CreateDhcpResponseAsync(req);

        Assert.Equal((byte)DhcpMessageType.Ack, ExtractMessageType(response));

        var span = response.Span;
        // ciaddr echoed at [12..16)
        Assert.Equal(new byte[] { 10, 0, 0, 77 }, span.Slice(12, 4).ToArray());
        // yiaddr zero at [16..20)
        Assert.Equal(new byte[] { 0, 0, 0, 0 }, span.Slice(16, 4).ToArray());
        // no lease-time / renewal / rebinding options
        Assert.False(HasOption(response, 51));
        Assert.False(HasOption(response, 58));
        Assert.False(HasOption(response, 59));
    }

    // ── Oversized option payloads from config ──────────────────────────

    [Fact]
    public async Task Discover_ConfigProducesOversizedOption_YieldsNak_NotCorruptPacket()
    {
        // A DHCP option length is one byte. An admin can configure a domain
        // search list whose RFC 1035 encoding exceeds 255 bytes — the old
        // WriteOption silently truncated the length byte and emitted a packet
        // every client mis-parses. Now packet construction throws and the
        // request is answered with a recoverable NAK.
        var domains = string.Join(",", Enumerable.Range(0, 20).Select(i => $"subdomain{i:00}.example.org"));
        var subnet = new DhcpSubnet
        {
            Id = Guid.NewGuid(),
            Name = "big",
            Network = "10.0.0.0/24",
            DefaultLeaseTime = 7200,
            DomainSearchList = domains
        };
        StubSubnetReturning(subnet);
        StubClassMatchNone();
        _subnets.Setup(s => s.FindAvailableIpInSubnetAsync(subnet, "aa:bb:cc:00:00:01",
                It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((IPAddress.Parse("10.0.0.50"), null));

        using var response = await CreateSvc().CreateDhcpResponseAsync(MakeRequest(DhcpMessageType.Discover));

        Assert.Equal((byte)DhcpMessageType.Nak, ExtractMessageType(response));
    }

    // ── NAK shape ──────────────────────────────────────────────────────

    [Fact]
    public async Task Nak_CarriesOnlyMessageTypeAndServerIdentifier()
    {
        StubSubnetReturning(null);
        StubClassMatchNone();
        _leases.Setup(l => l.CanAssignIpAsync(It.IsAny<string>(), It.IsAny<IPAddress>()))
            .ReturnsAsync(false);

        var req = MakeRequest(DhcpMessageType.Request);
        req.RequestedIp = IPAddress.Parse("10.0.0.150");

        using var response = await CreateSvc().CreateDhcpResponseAsync(req);

        Assert.Equal((byte)DhcpMessageType.Nak, ExtractMessageType(response));
        Assert.True(HasOption(response, 54));   // server identifier
        Assert.False(HasOption(response, 1));   // no subnet mask
        Assert.False(HasOption(response, 3));   // no router
        Assert.False(HasOption(response, 51));  // no lease time
    }
}
