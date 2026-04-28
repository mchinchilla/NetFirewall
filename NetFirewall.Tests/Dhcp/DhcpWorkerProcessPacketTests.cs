using System.Buffers;
using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.DhcpServer;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Behavioural coverage for <see cref="DhcpWorker.ProcessSinglePacketAsync"/> —
/// the per-packet pipeline that runs inside the channel consumer loop. We don't
/// touch sockets here; <c>IDhcpServerService.CreateDhcpResponseAsync</c> returns
/// an empty byte[] so the send path is bypassed (the worker only calls
/// <c>GetSendSocketForInterface</c> when <c>response.Length &gt; 0</c>). What we
/// pin is: the parsed request reaches the service, <c>SourceInterfaceName</c>
/// is threaded through from the packet context, and a malformed packet does NOT
/// invoke the service.
///
/// Plus two static-helper tests (<c>ParseResponseMessageType</c>,
/// <c>DetermineDestinationEndPoint</c>) that govern destination routing — those
/// don't need any DI scaffolding.
/// </summary>
public class DhcpWorkerProcessPacketTests
{
    private static byte[] BuildValidDiscover(byte mac6 = 0x01) =>
        BuildValidRequest(DhcpMessageType.Discover, mac6);

    private static byte[] BuildValidRequest(DhcpMessageType type, byte mac6 = 0x01)
    {
        var pkt = new byte[576];
        pkt[0] = 1;             // op = BOOTREQUEST
        pkt[1] = 1; pkt[2] = 6; // htype/hlen
        pkt[4] = 0xDE; pkt[5] = 0xAD; pkt[6] = 0xBE; pkt[7] = 0xEF; // xid
        pkt[28] = 0xAA; pkt[29] = 0xBB; pkt[30] = 0xCC;
        pkt[31] = 0x11; pkt[32] = 0x22; pkt[33] = mac6;
        pkt[236] = 99; pkt[237] = 130; pkt[238] = 83; pkt[239] = 99; // magic cookie
        // Option 53 = <type>, then End
        pkt[240] = 53; pkt[241] = 1; pkt[242] = (byte)type;
        pkt[243] = 0xFF;
        return pkt;
    }

    private static (DhcpWorker worker, Mock<IDhcpServerService> service) CreateWorkerWithMockService()
    {
        var service = new Mock<IDhcpServerService>(MockBehavior.Strict);
        // Default: empty response → worker skips the send path entirely.
        service.Setup(s => s.CreateDhcpResponseAsync(It.IsAny<DhcpRequest>())).ReturnsAsync(Array.Empty<byte>());

        var sp = new ServiceCollection()
            .AddScoped(_ => service.Object)
            .BuildServiceProvider();

        var config = new ConfigurationBuilder().Build();
        var worker = new DhcpWorker(NullLogger<DhcpWorker>.Instance, sp.GetRequiredService<IServiceScopeFactory>(), config);
        return (worker, service);
    }

    private static DhcpPacketContext WrapPacket(byte[] pkt, string? interfaceName)
    {
        // Use a real ArrayPool so Dispose works; size = packet length.
        var pool = ArrayPool<byte>.Shared;
        var rented = pool.Rent(pkt.Length);
        Array.Copy(pkt, rented, pkt.Length);
        return new DhcpPacketContext(rented, pkt.Length,
            new IPEndPoint(IPAddress.Loopback, 68), interfaceName, pool);
    }

    // ── Happy path ─────────────────────────────────────────────────────

    [Fact]
    public async Task ProcessSinglePacket_ValidDiscover_CallsServiceWithParsedRequest()
    {
        var (worker, service) = CreateWorkerWithMockService();
        DhcpRequest? captured = null;
        service.Setup(s => s.CreateDhcpResponseAsync(It.IsAny<DhcpRequest>()))
               .Callback<DhcpRequest>(r => captured = r)
               .ReturnsAsync(Array.Empty<byte>());

        using var ctx = WrapPacket(BuildValidDiscover(), interfaceName: "eth0");
        await worker.ProcessSinglePacketAsync(ctx, CancellationToken.None);

        service.Verify(s => s.CreateDhcpResponseAsync(It.IsAny<DhcpRequest>()), Times.Once);
        Assert.NotNull(captured);
        Assert.Equal(DhcpMessageType.Discover, captured!.MessageType);
        Assert.Equal("AA:BB:CC:11:22:01", captured.ClientMac);
    }

    [Fact]
    public async Task ProcessSinglePacket_ThreadsSourceInterfaceNameOntoRequest()
    {
        // The interface name must reach the service BEFORE response generation —
        // subnet selection in DhcpServerService keys on it. Regression: an
        // earlier refactor set SourceInterfaceName after the service call.
        var (worker, service) = CreateWorkerWithMockService();
        string? observedIface = null;
        service.Setup(s => s.CreateDhcpResponseAsync(It.IsAny<DhcpRequest>()))
               .Callback<DhcpRequest>(r => observedIface = r.SourceInterfaceName)
               .ReturnsAsync(Array.Empty<byte>());

        using var ctx = WrapPacket(BuildValidDiscover(), interfaceName: "eth1.lan");
        await worker.ProcessSinglePacketAsync(ctx, CancellationToken.None);

        Assert.Equal("eth1.lan", observedIface);
    }

    [Fact]
    public async Task ProcessSinglePacket_NullInterfaceName_StillCallsService()
    {
        // Windows path / legacy socket: interface name is null. The pipeline
        // must still complete (subnet service falls back to first match).
        var (worker, service) = CreateWorkerWithMockService();
        using var ctx = WrapPacket(BuildValidDiscover(), interfaceName: null);

        await worker.ProcessSinglePacketAsync(ctx, CancellationToken.None);

        service.Verify(s => s.CreateDhcpResponseAsync(
            It.Is<DhcpRequest>(r => r.SourceInterfaceName == null)), Times.Once);
    }

    // ── Failure paths ──────────────────────────────────────────────────

    [Fact]
    public async Task ProcessSinglePacket_BadMagicCookie_ServiceNeverCalled()
    {
        var (worker, service) = CreateWorkerWithMockService();
        var pkt = BuildValidDiscover();
        pkt[236] = 0xDE; pkt[237] = 0xAD; pkt[238] = 0xBE; pkt[239] = 0xEF; // wrong cookie
        using var ctx = WrapPacket(pkt, interfaceName: "eth0");

        await worker.ProcessSinglePacketAsync(ctx, CancellationToken.None);

        service.Verify(s => s.CreateDhcpResponseAsync(It.IsAny<DhcpRequest>()), Times.Never);
    }

    [Fact]
    public async Task ProcessSinglePacket_BootReply_NotARequest_ServiceNeverCalled()
    {
        // op=2 is BOOTREPLY (something a server would emit). The worker must
        // ignore replies — otherwise two NetFirewall instances on the same wire
        // could feed each other's packets back through the service.
        var (worker, service) = CreateWorkerWithMockService();
        var pkt = BuildValidDiscover();
        pkt[0] = 2; // op = BOOTREPLY
        using var ctx = WrapPacket(pkt, interfaceName: "eth0");

        await worker.ProcessSinglePacketAsync(ctx, CancellationToken.None);

        service.Verify(s => s.CreateDhcpResponseAsync(It.IsAny<DhcpRequest>()), Times.Never);
    }

    [Fact]
    public async Task ProcessSinglePacket_ServiceThrows_PropagatesToCaller()
    {
        // ProcessSinglePacketAsync deliberately does NOT swallow exceptions —
        // the caller (ProcessPacketsAsync) wraps each iteration in try/catch
        // so it can increment _errorsCount and continue draining the channel.
        // If we caught here, the error counter would never advance.
        var (worker, service) = CreateWorkerWithMockService();
        service.Setup(s => s.CreateDhcpResponseAsync(It.IsAny<DhcpRequest>()))
               .ThrowsAsync(new InvalidOperationException("DB down"));

        using var ctx = WrapPacket(BuildValidDiscover(), interfaceName: "eth0");

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            worker.ProcessSinglePacketAsync(ctx, CancellationToken.None));
    }

    // ── Empty service response: send path is bypassed ──────────────────

    [Fact]
    public async Task ProcessSinglePacket_ServiceReturnsEmpty_DoesNotTouchSocket()
    {
        // The whole reason we can run these tests without a real socket: the
        // worker only calls GetSendSocketForInterface when response.Length > 0.
        // If this guard ever moves, every test in this file would NRE on the
        // null _legacySendSocket. So pin the contract.
        var (worker, service) = CreateWorkerWithMockService();
        using var ctx = WrapPacket(BuildValidDiscover(), interfaceName: "eth0");

        // No throw == socket path was skipped.
        await worker.ProcessSinglePacketAsync(ctx, CancellationToken.None);
        service.Verify(s => s.CreateDhcpResponseAsync(It.IsAny<DhcpRequest>()), Times.Once);
    }

    // ── Static helpers: ParseResponseMessageType ───────────────────────

    [Theory]
    [InlineData(DhcpMessageType.Offer)]
    [InlineData(DhcpMessageType.Ack)]
    [InlineData(DhcpMessageType.Nak)]
    public void ParseResponseMessageType_FindsOption53_ForEachReplyType(DhcpMessageType type)
    {
        var resp = new byte[260];
        resp[236] = 99; resp[237] = 130; resp[238] = 83; resp[239] = 99;
        // Lay down a couple of irrelevant options first to exercise the walker.
        resp[240] = 1; resp[241] = 4; resp[242] = 255; resp[243] = 255; resp[244] = 255; resp[245] = 0;
        resp[246] = 53; resp[247] = 1; resp[248] = (byte)type;
        resp[249] = 0xFF;

        Assert.Equal(type, DhcpWorker.ParseResponseMessageType(resp));
    }

    [Fact]
    public void ParseResponseMessageType_TooShort_ReturnsZero()
    {
        // Anything below the magic-cookie + first-option floor (243) is junk.
        var resp = new byte[200];
        Assert.Equal((DhcpMessageType)0, DhcpWorker.ParseResponseMessageType(resp));
    }

    [Fact]
    public void ParseResponseMessageType_NoOption53_ReturnsZero()
    {
        var resp = new byte[260];
        // Just an End marker after the magic cookie — no Option 53.
        resp[240] = 0xFF;
        Assert.Equal((DhcpMessageType)0, DhcpWorker.ParseResponseMessageType(resp));
    }

    // ── Static helpers: DetermineDestinationEndPoint ───────────────────

    [Fact]
    public void DetermineDestination_BroadcastFlagSet_ReturnsLimitedBroadcast()
    {
        // RFC 2131 §4.1: a client setting the broadcast bit can't accept
        // unicast (its IP stack isn't configured yet). We must reply to
        // 255.255.255.255:68 regardless of CiAddr.
        var req = new DhcpRequest { Flags = 0x8000, CiAddr = IPAddress.Parse("10.0.0.5") };
        var dest = DhcpWorker.DetermineDestinationEndPoint(req, new IPEndPoint(IPAddress.Loopback, 68));

        Assert.Equal(IPAddress.Broadcast, dest.Address);
        Assert.Equal(68, dest.Port);
    }

    [Fact]
    public void DetermineDestination_CiAddrZero_ReturnsBroadcast()
    {
        // No CiAddr means the client is mid-bootstrap → broadcast.
        var req = new DhcpRequest { Flags = 0, CiAddr = IPAddress.Any };
        var dest = DhcpWorker.DetermineDestinationEndPoint(req, new IPEndPoint(IPAddress.Loopback, 68));

        Assert.Equal(IPAddress.Broadcast, dest.Address);
    }

    [Fact]
    public void DetermineDestination_CiAddrPresent_NoBroadcastFlag_UnicastsToClient()
    {
        // Renewal case: client already has an IP and didn't request broadcast.
        var req = new DhcpRequest { Flags = 0, CiAddr = IPAddress.Parse("10.0.0.5") };
        var dest = DhcpWorker.DetermineDestinationEndPoint(req, new IPEndPoint(IPAddress.Loopback, 68));

        Assert.Equal(IPAddress.Parse("10.0.0.5"), dest.Address);
        Assert.Equal(68, dest.Port);
    }

    [Fact]
    public void DetermineDestination_CiAddrNull_TreatedAsBroadcast()
    {
        // Defensive: a request that somehow has a null CiAddr (parser path
        // shouldn't produce this, but the helper has to cope anyway).
        var req = new DhcpRequest { Flags = 0, CiAddr = null! };
        var dest = DhcpWorker.DetermineDestinationEndPoint(req, new IPEndPoint(IPAddress.Loopback, 68));

        Assert.Equal(IPAddress.Broadcast, dest.Address);
    }

    // ── Per-message-type counters ──────────────────────────────────────
    //
    // These pin the observable side-effect of ProcessSinglePacketAsync: every
    // recognized inbound message type bumps the corresponding counter exactly
    // once. The same counters feed ReportStatisticsAsync's hourly log line and
    // any future telemetry endpoint, so a regression here would silently break
    // operational monitoring.

    [Theory]
    [InlineData(DhcpMessageType.Discover)]
    [InlineData(DhcpMessageType.Request)]
    [InlineData(DhcpMessageType.Release)]
    public async Task ProcessSinglePacket_BumpsExactlyOneRequestCounter_PerMessageType(DhcpMessageType type)
    {
        var (worker, _) = CreateWorkerWithMockService();
        using var ctx = WrapPacket(BuildValidRequest(type), interfaceName: "eth0");

        await worker.ProcessSinglePacketAsync(ctx, CancellationToken.None);

        // Only the matching counter should advance — the rest stay at zero.
        Assert.Equal(type == DhcpMessageType.Discover ? 1 : 0, worker.DiscoverCount);
        Assert.Equal(type == DhcpMessageType.Request  ? 1 : 0, worker.RequestCount);
        Assert.Equal(type == DhcpMessageType.Release  ? 1 : 0, worker.ReleaseCount);
    }

    [Fact]
    public async Task ProcessSinglePacket_DeclineAndInform_DoNotBumpRequestCounters()
    {
        // Decline / Inform are valid DHCP types but the worker only tracks the
        // three "interesting" inbound types (Discover/Request/Release). Pin
        // that the switch doesn't accidentally count them under another label.
        var (worker, _) = CreateWorkerWithMockService();

        using (var ctx = WrapPacket(BuildValidRequest(DhcpMessageType.Decline), "eth0"))
            await worker.ProcessSinglePacketAsync(ctx, CancellationToken.None);
        using (var ctx = WrapPacket(BuildValidRequest(DhcpMessageType.Inform), "eth0"))
            await worker.ProcessSinglePacketAsync(ctx, CancellationToken.None);

        Assert.Equal(0, worker.DiscoverCount);
        Assert.Equal(0, worker.RequestCount);
        Assert.Equal(0, worker.ReleaseCount);
    }

    [Fact]
    public async Task ProcessSinglePacket_BadMagicCookie_NoCountersAdvance()
    {
        // Parser-rejection happens before the message-type switch. Pin that
        // the counters stay at zero — otherwise a flood of malformed packets
        // would inflate "DISCOVER count" in the stats log.
        var (worker, _) = CreateWorkerWithMockService();
        var pkt = BuildValidDiscover();
        pkt[236] = 0xDE; pkt[237] = 0xAD; pkt[238] = 0xBE; pkt[239] = 0xEF;
        using var ctx = WrapPacket(pkt, interfaceName: "eth0");

        await worker.ProcessSinglePacketAsync(ctx, CancellationToken.None);

        Assert.Equal(0, worker.DiscoverCount);
        Assert.Equal(0, worker.RequestCount);
        Assert.Equal(0, worker.ReleaseCount);
    }

    [Fact]
    public async Task ProcessSinglePacket_RepeatedDiscovers_AccumulateCount()
    {
        // Sanity: counters are cumulative across calls (Interlocked.Increment,
        // not assigned). A regression to `_discoverCount = 1` would pass the
        // single-call tests but show up here.
        var (worker, _) = CreateWorkerWithMockService();
        for (var i = 0; i < 5; i++)
        {
            using var ctx = WrapPacket(BuildValidDiscover((byte)i), interfaceName: "eth0");
            await worker.ProcessSinglePacketAsync(ctx, CancellationToken.None);
        }

        Assert.Equal(5, worker.DiscoverCount);
    }
}
