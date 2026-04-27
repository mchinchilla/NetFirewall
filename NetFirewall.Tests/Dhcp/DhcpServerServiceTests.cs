using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Mock-only coverage of <see cref="DhcpServerService"/> — the orchestrator.
/// Verifies that each DHCP message type drives the right calls into the
/// leases/subnet/failover services and yields the expected response message
/// type. Byte-level packet construction is exercised indirectly: we just
/// extract the option-53 message type to confirm intent.
/// </summary>
public class DhcpServerServiceTests
{
    private readonly Mock<IDhcpLeasesService> _leases = new(MockBehavior.Strict);
    private readonly Mock<IDhcpSubnetService> _subnets = new(MockBehavior.Strict);
    private readonly Mock<IFailoverService> _failover = new(MockBehavior.Strict);

    private DhcpServerService CreateSvc(bool withFailover = false) =>
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
            }),
            withFailover ? _failover.Object : null);

    private static DhcpRequest MakeRequest(DhcpMessageType type, IPAddress? requested = null) => new()
    {
        ClientMac = "aa:bb:cc:00:00:01",
        ChAddr = new byte[] { 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        Xid = new byte[] { 1, 2, 3, 4 },
        CiAddr = IPAddress.Any,
        YiAddr = IPAddress.Any,
        SiAddr = IPAddress.Any,
        GiAddr = IPAddress.Any,
        RequestedIp = requested ?? IPAddress.Any,
        MessageType = type,
        Hostname = "client",
        ParameterRequestList = Array.Empty<byte>()
    };

    /// <summary>
    /// Walk past the BOOTP fixed header + magic cookie and locate the option-53
    /// (DHCP message type) byte. Returns null if the response is empty.
    /// </summary>
    private static byte? ExtractMessageType(byte[] response)
    {
        if (response.Length == 0) return null;
        var i = 240; // standard offset post-fixed-header + magic cookie
        for (; i < response.Length - 1; i++)
        {
            if (response[i] == 53 && response[i + 1] == 1)
                return response[i + 2];
            if (response[i] == 0xFF) break;
        }
        return null;
    }

    private void StubSubnetReturning(DhcpSubnet? subnet) =>
        _subnets.Setup(s => s.FindSubnetForRequestAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(subnet);

    private void StubClassMatchNone() =>
        _subnets.Setup(s => s.MatchClientClassAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((DhcpClass?)null);

    // ── DISCOVER ───────────────────────────────────────────────────────

    [Fact]
    public async Task Discover_FallbackPath_OffersIp_FromLeasesService()
    {
        StubSubnetReturning(null);
        StubClassMatchNone();
        _leases.Setup(l => l.OfferLeaseAsync("aa:bb:cc:00:00:01",
                It.IsAny<IPAddress>(), It.IsAny<IPAddress>()))
            .ReturnsAsync(IPAddress.Parse("10.0.0.150"));

        var response = await CreateSvc().CreateDhcpResponseAsync(MakeRequest(DhcpMessageType.Discover));

        Assert.Equal((byte)DhcpMessageType.Offer, ExtractMessageType(response));
        _leases.Verify(l => l.OfferLeaseAsync(It.IsAny<string>(), It.IsAny<IPAddress>(), It.IsAny<IPAddress>()), Times.Once);
    }

    [Fact]
    public async Task Discover_SubnetPath_FindsAvailableIpInSubnet()
    {
        var subnet = new DhcpSubnet { Id = Guid.NewGuid(), Name = "home", Network = "10.0.0.0/24", DefaultLeaseTime = 7200 };
        StubSubnetReturning(subnet);
        StubClassMatchNone();
        _subnets.Setup(s => s.FindAvailableIpInSubnetAsync(subnet, "aa:bb:cc:00:00:01",
                It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((IPAddress.Parse("10.0.0.50"), null));

        var response = await CreateSvc().CreateDhcpResponseAsync(MakeRequest(DhcpMessageType.Discover));

        Assert.Equal((byte)DhcpMessageType.Offer, ExtractMessageType(response));
        // Falls back to leases path NOT used when subnet is present.
        _leases.Verify(l => l.OfferLeaseAsync(It.IsAny<string>(), It.IsAny<IPAddress>(), It.IsAny<IPAddress>()), Times.Never);
    }

    [Fact]
    public async Task Discover_NoIpAvailable_ReturnsNak()
    {
        StubSubnetReturning(null);
        StubClassMatchNone();
        _leases.Setup(l => l.OfferLeaseAsync(It.IsAny<string>(), It.IsAny<IPAddress>(), It.IsAny<IPAddress>()))
            .ReturnsAsync((IPAddress?)null);

        var response = await CreateSvc().CreateDhcpResponseAsync(MakeRequest(DhcpMessageType.Discover));

        Assert.Equal((byte)DhcpMessageType.Nak, ExtractMessageType(response));
    }

    [Fact]
    public async Task Discover_FailoverCantServe_ReturnsEmpty_NoIpLookup()
    {
        StubSubnetReturning(null);
        StubClassMatchNone();
        _failover.Setup(f => f.IsEnabled).Returns(true);
        _failover.Setup(f => f.CanServe).Returns(false);

        var response = await CreateSvc(withFailover: true).CreateDhcpResponseAsync(MakeRequest(DhcpMessageType.Discover));

        Assert.Empty(response);
        _leases.Verify(l => l.OfferLeaseAsync(It.IsAny<string>(), It.IsAny<IPAddress>(), It.IsAny<IPAddress>()), Times.Never);
    }

    [Fact]
    public async Task Discover_FailoverDeniesByLoadBalance_ReturnsEmpty()
    {
        StubSubnetReturning(null);
        StubClassMatchNone();
        _failover.Setup(f => f.IsEnabled).Returns(true);
        _failover.Setup(f => f.CanServe).Returns(true);
        _failover.Setup(f => f.ShouldHandleRequest(It.IsAny<string>(), It.IsAny<IPAddress?>())).Returns(false);

        var response = await CreateSvc(withFailover: true).CreateDhcpResponseAsync(MakeRequest(DhcpMessageType.Discover));

        Assert.Empty(response);
    }

    // ── REQUEST ────────────────────────────────────────────────────────

    [Fact]
    public async Task Request_CanAssign_AssignsLeaseAndReturnsAck()
    {
        StubSubnetReturning(null);
        StubClassMatchNone();
        var requestedIp = IPAddress.Parse("10.0.0.150");
        _leases.Setup(l => l.CanAssignIpAsync("aa:bb:cc:00:00:01", requestedIp)).ReturnsAsync(true);
        _leases.Setup(l => l.AssignLeaseAsync("aa:bb:cc:00:00:01", requestedIp, It.IsAny<int>(), "client"))
            .Returns(Task.CompletedTask);

        var response = await CreateSvc().CreateDhcpResponseAsync(MakeRequest(DhcpMessageType.Request, requestedIp));

        Assert.Equal((byte)DhcpMessageType.Ack, ExtractMessageType(response));
        _leases.Verify(l => l.AssignLeaseAsync("aa:bb:cc:00:00:01", requestedIp, It.IsAny<int>(), "client"), Times.Once);
    }

    [Fact]
    public async Task Request_CannotAssign_ReturnsNak()
    {
        StubSubnetReturning(null);
        StubClassMatchNone();
        var requestedIp = IPAddress.Parse("10.0.0.150");
        _leases.Setup(l => l.CanAssignIpAsync("aa:bb:cc:00:00:01", requestedIp)).ReturnsAsync(false);

        var response = await CreateSvc().CreateDhcpResponseAsync(MakeRequest(DhcpMessageType.Request, requestedIp));

        Assert.Equal((byte)DhcpMessageType.Nak, ExtractMessageType(response));
        _leases.Verify(l => l.AssignLeaseAsync(It.IsAny<string>(), It.IsAny<IPAddress>(), It.IsAny<int>(), It.IsAny<string?>()), Times.Never);
    }

    [Fact]
    public async Task Request_NoRequestedIp_FallsBackToExistingLease()
    {
        StubSubnetReturning(null);
        StubClassMatchNone();
        var existing = IPAddress.Parse("10.0.0.150");
        _leases.Setup(l => l.GetAssignedIpAsync("aa:bb:cc:00:00:01")).ReturnsAsync(existing);
        _leases.Setup(l => l.CanAssignIpAsync("aa:bb:cc:00:00:01", existing)).ReturnsAsync(true);
        _leases.Setup(l => l.AssignLeaseAsync(It.IsAny<string>(), existing, It.IsAny<int>(), It.IsAny<string?>()))
            .Returns(Task.CompletedTask);

        var req = MakeRequest(DhcpMessageType.Request);
        req.RequestedIp = null!;

        var response = await CreateSvc().CreateDhcpResponseAsync(req);

        Assert.Equal((byte)DhcpMessageType.Ack, ExtractMessageType(response));
    }

    // ── RELEASE ────────────────────────────────────────────────────────

    [Fact]
    public async Task Release_CallsReleaseAndReturnsEmpty()
    {
        StubSubnetReturning(null);
        StubClassMatchNone();
        _leases.Setup(l => l.GetAssignedIpAsync(It.IsAny<string>())).ReturnsAsync(IPAddress.Parse("10.0.0.150"));
        _leases.Setup(l => l.ReleaseLeaseAsync("aa:bb:cc:00:00:01")).Returns(Task.CompletedTask);

        var response = await CreateSvc().CreateDhcpResponseAsync(MakeRequest(DhcpMessageType.Release));

        Assert.Empty(response); // RFC: server doesn't reply to RELEASE
        _leases.Verify(l => l.ReleaseLeaseAsync("aa:bb:cc:00:00:01"), Times.Once);
    }

    // ── DECLINE ────────────────────────────────────────────────────────

    [Fact]
    public async Task Decline_MarksIpAsDeclined_ReturnsEmpty()
    {
        StubSubnetReturning(null);
        StubClassMatchNone();
        var ip = IPAddress.Parse("10.0.0.150");
        _leases.Setup(l => l.MarkIpAsDeclinedAsync(ip)).Returns(Task.CompletedTask);

        var response = await CreateSvc().CreateDhcpResponseAsync(MakeRequest(DhcpMessageType.Decline, ip));

        Assert.Empty(response);
        _leases.Verify(l => l.MarkIpAsDeclinedAsync(ip), Times.Once);
    }

    // ── INFORM ─────────────────────────────────────────────────────────

    [Fact]
    public async Task Inform_ReturnsAckWithoutAssigningLease()
    {
        StubSubnetReturning(null);
        StubClassMatchNone();
        var ip = IPAddress.Parse("10.0.0.150");

        var response = await CreateSvc().CreateDhcpResponseAsync(MakeRequest(DhcpMessageType.Inform, ip));

        Assert.Equal((byte)DhcpMessageType.Ack, ExtractMessageType(response));
        _leases.Verify(l => l.AssignLeaseAsync(It.IsAny<string>(), It.IsAny<IPAddress>(), It.IsAny<int>(), It.IsAny<string?>()), Times.Never);
    }

    // ── unknown / error paths ──────────────────────────────────────────

    [Fact]
    public async Task UnknownMessageType_ReturnsNak()
    {
        StubSubnetReturning(null);
        StubClassMatchNone();

        // 99 is not a real DHCP message type — defaults to NAK in the switch.
        var req = MakeRequest((DhcpMessageType)99);
        var response = await CreateSvc().CreateDhcpResponseAsync(req);

        Assert.Equal((byte)DhcpMessageType.Nak, ExtractMessageType(response));
    }

    [Fact]
    public async Task ExceptionInPipeline_ReturnsNak_NotPropagated()
    {
        // FindSubnetForRequestAsync throws — must be caught and converted to NAK.
        _subnets.Setup(s => s.FindSubnetForRequestAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("boom"));

        var response = await CreateSvc().CreateDhcpResponseAsync(MakeRequest(DhcpMessageType.Discover));

        Assert.Equal((byte)DhcpMessageType.Nak, ExtractMessageType(response));
    }
}
