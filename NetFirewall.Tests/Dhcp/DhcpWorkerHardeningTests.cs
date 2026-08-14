using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.DhcpServer;
using NetFirewall.Models.Dhcp;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Regression coverage for the parser/routing hardening pass:
/// - packets of 236-239 bytes used to throw IndexOutOfRange on the magic-cookie
///   read (they pass the MinDhcpPacketSize=236 check but the cookie lives at
///   [236..240));
/// - option 54 (server identifier) was not parsed at all, so REQUESTs addressed
///   to another DHCP server were answered anyway;
/// - responses to relayed requests (giaddr != 0) were broadcast on the local
///   segment instead of unicast to the relay on port 67;
/// - NAKs were unicast to the client's (by definition suspect) ciaddr.
/// </summary>
public class DhcpWorkerHardeningTests
{
    private static DhcpWorker CreateWorker()
    {
        var sp = new ServiceCollection().BuildServiceProvider();
        var config = new ConfigurationBuilder().Build();
        return new DhcpWorker(NullLogger<DhcpWorker>.Instance, sp.GetRequiredService<IServiceScopeFactory>(), config);
    }

    private static readonly IPEndPoint AnyEndPoint = new(IPAddress.Loopback, 68);

    private static byte[] BuildPacketWithRawOptions(byte[] options)
    {
        var pkt = new byte[240 + Math.Max(options.Length, 64)];
        pkt[0] = 1;             // op = BOOTREQUEST
        pkt[1] = 1; pkt[2] = 6; // htype/hlen
        pkt[28] = 0xAA; pkt[29] = 0xBB; pkt[30] = 0xCC; pkt[31] = 0x00; pkt[32] = 0x00; pkt[33] = 0x01;
        pkt[236] = 99; pkt[237] = 130; pkt[238] = 83; pkt[239] = 99; // magic cookie
        Array.Copy(options, 0, pkt, 240, options.Length);
        return pkt;
    }

    // ── Length guard: 236-239 byte packets must not throw ──────────────

    [Theory]
    [InlineData(236)]
    [InlineData(237)]
    [InlineData(238)]
    [InlineData(239)]
    public void TryParse_PacketShorterThanOptionsOffset_ReturnsFalse_NoThrow(int length)
    {
        // A BOOTP-style packet with fixed header but no magic cookie: the old
        // code indexed buffer[236] after only checking >= 236 and threw.
        var pkt = new byte[length];
        pkt[0] = 1;

        var ok = CreateWorker().TryParseDhcpRequest(pkt, AnyEndPoint, out _);

        Assert.False(ok);
    }

    [Fact]
    public void TryParse_Exactly240Bytes_WithCookie_Parses()
    {
        // 240 bytes = fixed header + cookie, zero options. Legal boundary.
        var pkt = new byte[240];
        pkt[0] = 1; pkt[1] = 1; pkt[2] = 6;
        pkt[236] = 99; pkt[237] = 130; pkt[238] = 83; pkt[239] = 99;

        Assert.True(CreateWorker().TryParseDhcpRequest(pkt, AnyEndPoint, out var req));
        Assert.Equal((DhcpMessageType)0, req.MessageType);
        Assert.True(req.IsBootp); // no option 53 + op=1
    }

    // ── Nullable option defaults ───────────────────────────────────────

    [Fact]
    public void TryParse_NoOptions_AbsentOptionFieldsAreNull()
    {
        // "The client did not send it" must be null, not ""/0.0.0.0 — the
        // 0.0.0.0 default previously made every renewal-without-option-50 look
        // like a request for the zero address (NAK on renew).
        var pkt = BuildPacketWithRawOptions(new byte[] { 0xFF });

        Assert.True(CreateWorker().TryParseDhcpRequest(pkt, AnyEndPoint, out var req));
        Assert.Null(req.RequestedIp);
        Assert.Null(req.Hostname);
        Assert.Null(req.VendorClassIdentifier);
        Assert.Null(req.ClientIdentifier);
        Assert.Null(req.ParameterRequestList);
        Assert.Null(req.ServerIdentifier);
    }

    // ── Option 54: server identifier ───────────────────────────────────

    [Fact]
    public void TryParse_Option54_PopulatesServerIdentifier()
    {
        var opts = new byte[] {
            53, 1, (byte)DhcpMessageType.Request,
            54, 4, 10, 0, 0, 1,
            0xFF
        };
        var pkt = BuildPacketWithRawOptions(opts);

        Assert.True(CreateWorker().TryParseDhcpRequest(pkt, AnyEndPoint, out var req));
        Assert.Equal(IPAddress.Parse("10.0.0.1"), req.ServerIdentifier);
    }

    [Fact]
    public void TryParse_Option54_TooShort_Ignored()
    {
        var opts = new byte[] {
            53, 1, (byte)DhcpMessageType.Request,
            54, 2, 10, 0,
            0xFF
        };
        var pkt = BuildPacketWithRawOptions(opts);

        Assert.True(CreateWorker().TryParseDhcpRequest(pkt, AnyEndPoint, out var req));
        Assert.Null(req.ServerIdentifier);
    }

    // ── Destination routing: relay agents ──────────────────────────────

    [Fact]
    public void DetermineDestination_GiaddrSet_UnicastsToRelayOnPort67()
    {
        // RFC 2131 §4.1: giaddr != 0 → reply through the relay agent. The
        // relayed client is on ANOTHER segment; broadcasting here reaches
        // nobody.
        var req = new DhcpRequest
        {
            Flags = 0,
            CiAddr = IPAddress.Any,
            GiAddr = IPAddress.Parse("172.16.5.1")
        };

        var dest = DhcpWorker.DetermineDestinationEndPoint(req, DhcpMessageType.Offer, AnyEndPoint);

        Assert.Equal(IPAddress.Parse("172.16.5.1"), dest.Address);
        Assert.Equal(67, dest.Port);
    }

    [Fact]
    public void DetermineDestination_GiaddrSet_WinsOverBroadcastFlag()
    {
        var req = new DhcpRequest
        {
            Flags = 0x8000, // broadcast requested — but the client is remote
            CiAddr = IPAddress.Any,
            GiAddr = IPAddress.Parse("172.16.5.1")
        };

        var dest = DhcpWorker.DetermineDestinationEndPoint(req, DhcpMessageType.Offer, AnyEndPoint);

        Assert.Equal(IPAddress.Parse("172.16.5.1"), dest.Address);
        Assert.Equal(67, dest.Port);
    }

    // ── Destination routing: NAK must broadcast ────────────────────────

    [Fact]
    public void DetermineDestination_Nak_Broadcasts_EvenWithCiAddr()
    {
        // The whole point of a NAK is that the client's addressing state is
        // wrong — unicasting to the address we just rejected may never arrive.
        var req = new DhcpRequest
        {
            Flags = 0,
            CiAddr = IPAddress.Parse("10.0.0.50"),
            GiAddr = IPAddress.Any
        };

        var dest = DhcpWorker.DetermineDestinationEndPoint(req, DhcpMessageType.Nak, AnyEndPoint);

        Assert.Equal(IPAddress.Broadcast, dest.Address);
        Assert.Equal(68, dest.Port);
    }

    [Fact]
    public void DetermineDestination_Nak_ForRelayedClient_StillGoesToRelay()
    {
        // Relay beats NAK-broadcast: the relay forwards to the right segment.
        var req = new DhcpRequest
        {
            Flags = 0,
            CiAddr = IPAddress.Parse("10.0.0.50"),
            GiAddr = IPAddress.Parse("172.16.5.1")
        };

        var dest = DhcpWorker.DetermineDestinationEndPoint(req, DhcpMessageType.Nak, AnyEndPoint);

        Assert.Equal(IPAddress.Parse("172.16.5.1"), dest.Address);
        Assert.Equal(67, dest.Port);
    }

    [Fact]
    public void DetermineDestination_Ack_WithCiAddr_StillUnicasts()
    {
        // Sanity: the NAK special-case must not leak into ACK routing.
        var req = new DhcpRequest { Flags = 0, CiAddr = IPAddress.Parse("10.0.0.50"), GiAddr = IPAddress.Any };

        var dest = DhcpWorker.DetermineDestinationEndPoint(req, DhcpMessageType.Ack, AnyEndPoint);

        Assert.Equal(IPAddress.Parse("10.0.0.50"), dest.Address);
        Assert.Equal(68, dest.Port);
    }
}
