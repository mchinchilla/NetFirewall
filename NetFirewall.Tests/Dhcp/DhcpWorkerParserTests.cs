using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.DhcpServer;
using NetFirewall.Models.Dhcp;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Coverage of <see cref="DhcpWorker"/>'s zero-allocation packet parser.
/// We exercise the parser directly with hand-crafted byte buffers — no UDP
/// socket, no service container — so we can hit every branch of the BOOTP
/// header and DHCP options decoding.
/// </summary>
public class DhcpWorkerParserTests
{
    /// <summary>Construct a worker just for its parsing methods (no I/O performed).</summary>
    private static DhcpWorker CreateWorker()
    {
        var sp = new ServiceCollection().BuildServiceProvider();
        var config = new ConfigurationBuilder().Build();
        return new DhcpWorker(NullLogger<DhcpWorker>.Instance, sp.GetRequiredService<IServiceScopeFactory>(), config);
    }

    /// <summary>
    /// Build a minimum-viable DHCP packet (300 bytes incl. options) with the
    /// given message type and MAC. Caller can mutate further before parsing.
    /// </summary>
    private static byte[] BuildPacket(
        DhcpMessageType type,
        byte[] mac,
        IPAddress? ciAddr = null,
        IPAddress? giAddr = null,
        IPAddress? requestedIp = null,
        string? hostname = null,
        ushort flags = 0)
    {
        // 240-byte fixed header + magic cookie at 236..239 + options + 0xFF terminator.
        var pkt = new byte[576];
        pkt[0] = 1;                  // op = BOOTREQUEST
        pkt[1] = 1;                  // htype = ethernet
        pkt[2] = 6;                  // hlen
        pkt[3] = 0;                  // hops

        pkt[4] = 0xDE; pkt[5] = 0xAD; pkt[6] = 0xBE; pkt[7] = 0xEF;  // xid
        pkt[10] = (byte)((flags >> 8) & 0xFF);
        pkt[11] = (byte)(flags & 0xFF);

        if (ciAddr is not null) Array.Copy(ciAddr.GetAddressBytes(), 0, pkt, 12, 4);
        if (giAddr is not null) Array.Copy(giAddr.GetAddressBytes(), 0, pkt, 24, 4);
        Array.Copy(mac, 0, pkt, 28, 6); // chaddr (16 bytes total, MAC in first 6)

        // Magic cookie
        pkt[236] = 99; pkt[237] = 130; pkt[238] = 83; pkt[239] = 99;

        var i = 240;
        // Option 53: Message Type
        pkt[i++] = 53; pkt[i++] = 1; pkt[i++] = (byte)type;

        if (hostname is not null)
        {
            // Option 12: Host Name
            var bytes = System.Text.Encoding.ASCII.GetBytes(hostname);
            pkt[i++] = 12; pkt[i++] = (byte)bytes.Length;
            Array.Copy(bytes, 0, pkt, i, bytes.Length);
            i += bytes.Length;
        }
        if (requestedIp is not null)
        {
            // Option 50: Requested IP
            var bytes = requestedIp.GetAddressBytes();
            pkt[i++] = 50; pkt[i++] = 4;
            Array.Copy(bytes, 0, pkt, i, 4); i += 4;
        }

        pkt[i] = 0xFF; // End option
        return pkt;
    }

    private static readonly IPEndPoint AnyEndPoint = new(IPAddress.Loopback, 68);

    // ── Happy paths ────────────────────────────────────────────────────

    [Fact]
    public void TryParse_ValidDiscover_PopulatesAllHeaderFields()
    {
        var worker = CreateWorker();
        var pkt = BuildPacket(DhcpMessageType.Discover, new byte[] { 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01 });

        Assert.True(worker.TryParseDhcpRequest(pkt, AnyEndPoint, out var req));

        Assert.Equal(DhcpMessageType.Discover, req.MessageType);
        Assert.Equal("AA:BB:CC:00:00:01", req.ClientMac);
        Assert.Equal(new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }, req.Xid);
        Assert.Equal(1, req.Op);
        Assert.Equal(1, req.HType);
        Assert.Equal(6, req.HLen);
        Assert.False(req.IsBootp);
    }

    [Fact]
    public void TryParse_RequestWithRequestedIpAndHostname_ParsesOptions()
    {
        var worker = CreateWorker();
        var pkt = BuildPacket(
            DhcpMessageType.Request,
            mac: new byte[] { 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01 },
            requestedIp: IPAddress.Parse("10.0.0.42"),
            hostname: "laptop");

        Assert.True(worker.TryParseDhcpRequest(pkt, AnyEndPoint, out var req));

        Assert.Equal(DhcpMessageType.Request, req.MessageType);
        Assert.Equal("10.0.0.42", req.RequestedIp.ToString());
        Assert.Equal("laptop", req.Hostname);
    }

    [Fact]
    public void TryParse_PacketWithGiAddrAndCiAddr_ExtractsBoth()
    {
        var worker = CreateWorker();
        var pkt = BuildPacket(
            DhcpMessageType.Discover,
            new byte[] { 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01 },
            ciAddr: IPAddress.Parse("192.168.1.50"),
            giAddr: IPAddress.Parse("10.0.0.1"));

        Assert.True(worker.TryParseDhcpRequest(pkt, AnyEndPoint, out var req));
        Assert.Equal("192.168.1.50", req.CiAddr.ToString());
        Assert.Equal("10.0.0.1", req.GiAddr.ToString());
    }

    [Fact]
    public void TryParse_BroadcastFlagSet_IsExposedInRequest()
    {
        var worker = CreateWorker();
        var pkt = BuildPacket(DhcpMessageType.Discover,
            new byte[] { 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01 }, flags: 0x8000);

        Assert.True(worker.TryParseDhcpRequest(pkt, AnyEndPoint, out var req));
        Assert.Equal(0x8000, req.Flags);
    }

    // ── Negative paths ─────────────────────────────────────────────────

    [Fact]
    public void TryParse_BufferTooShort_ReturnsFalse()
    {
        var worker = CreateWorker();
        var pkt = new byte[100]; // < MinDhcpPacketSize

        Assert.False(worker.TryParseDhcpRequest(pkt, AnyEndPoint, out _));
    }

    [Fact]
    public void TryParse_BadMagicCookie_ReturnsFalse()
    {
        var worker = CreateWorker();
        var pkt = BuildPacket(DhcpMessageType.Discover, new byte[] { 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01 });
        pkt[236] = 0; pkt[237] = 0; pkt[238] = 0; pkt[239] = 0;

        Assert.False(worker.TryParseDhcpRequest(pkt, AnyEndPoint, out _));
    }

    [Fact]
    public void TryParse_BootreplyOpcode_IgnoredAsNonRequest()
    {
        var worker = CreateWorker();
        var pkt = BuildPacket(DhcpMessageType.Discover, new byte[] { 0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01 });
        pkt[0] = 2; // BOOTREPLY — server-to-client; we should not parse our own replies

        Assert.False(worker.TryParseDhcpRequest(pkt, AnyEndPoint, out _));
    }

    // ── ParseResponseMessageType ───────────────────────────────────────

    [Theory]
    [InlineData(DhcpMessageType.Offer)]
    [InlineData(DhcpMessageType.Ack)]
    [InlineData(DhcpMessageType.Nak)]
    public void ParseResponseMessageType_FindsOption53AcrossOptions(DhcpMessageType expected)
    {
        // Build a server response: BOOTREPLY (op=2) + magic cookie + filler options + msg type at the end.
        var pkt = new byte[300];
        pkt[0] = 2;
        pkt[236] = 99; pkt[237] = 130; pkt[238] = 83; pkt[239] = 99;

        var i = 240;
        // Some filler options before option-53 to verify the walker isn't anchored at offset 240.
        pkt[i++] = 1; pkt[i++] = 4; i += 4;       // subnet mask placeholder
        pkt[i++] = 51; pkt[i++] = 4; i += 4;      // lease time placeholder
        pkt[i++] = 53; pkt[i++] = 1; pkt[i++] = (byte)expected; // option 53
        pkt[i] = 0xFF;

        var actual = DhcpWorker.ParseResponseMessageType(pkt);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ParseResponseMessageType_TooShort_ReturnsZero()
    {
        // <243 bytes — service should bail out without scanning.
        var pkt = new byte[100];
        Assert.Equal((DhcpMessageType)0, DhcpWorker.ParseResponseMessageType(pkt));
    }

    [Fact]
    public void ParseResponseMessageType_PadOptionsSkipped()
    {
        var pkt = new byte[300];
        pkt[236] = 99; pkt[237] = 130; pkt[238] = 83; pkt[239] = 99;
        pkt[240] = 0;  // pad
        pkt[241] = 0;  // pad
        pkt[242] = 53; pkt[243] = 1; pkt[244] = (byte)DhcpMessageType.Ack;
        pkt[245] = 0xFF;

        Assert.Equal(DhcpMessageType.Ack, DhcpWorker.ParseResponseMessageType(pkt));
    }

    // ── DetermineDestinationEndPoint ───────────────────────────────────

    [Fact]
    public void DetermineDestination_BroadcastFlag_RoutesToBroadcast()
    {
        var req = new DhcpRequest
        {
            Flags = 0x8000,
            CiAddr = IPAddress.Parse("10.0.0.5") // even with a CIaddr, broadcast wins
        };

        var ep = DhcpWorker.DetermineDestinationEndPoint(req, new IPEndPoint(IPAddress.Loopback, 68));
        Assert.Equal(IPAddress.Broadcast, ep.Address);
        Assert.Equal(68, ep.Port);
    }

    [Fact]
    public void DetermineDestination_NoCiAddr_RoutesToBroadcast()
    {
        var req = new DhcpRequest { Flags = 0, CiAddr = IPAddress.Any };
        var ep = DhcpWorker.DetermineDestinationEndPoint(req, new IPEndPoint(IPAddress.Loopback, 68));
        Assert.Equal(IPAddress.Broadcast, ep.Address);
    }

    [Fact]
    public void DetermineDestination_HasCiAddr_AndNoBroadcastFlag_RoutesUnicast()
    {
        var req = new DhcpRequest { Flags = 0, CiAddr = IPAddress.Parse("10.0.0.5") };
        var ep = DhcpWorker.DetermineDestinationEndPoint(req, new IPEndPoint(IPAddress.Loopback, 68));
        Assert.Equal("10.0.0.5", ep.Address.ToString());
        Assert.Equal(68, ep.Port);
    }

    // ── FormatMacAddress (zero-alloc helper) ───────────────────────────

    [Fact]
    public void FormatMacAddress_RendersUppercaseHexWithColons()
    {
        var bytes = new byte[] { 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };
        Assert.Equal("AA:BB:CC:DD:EE:FF", DhcpWorker.FormatMacAddress(bytes));
    }

    [Fact]
    public void FormatMacAddress_AllZeros_RendersAllZeros()
    {
        Assert.Equal("00:00:00:00:00:00", DhcpWorker.FormatMacAddress(new byte[6]));
    }

    [Fact]
    public void FormatMacAddress_MixedNibbles_PreservesByteOrder()
    {
        var bytes = new byte[] { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB };
        Assert.Equal("01:23:45:67:89:AB", DhcpWorker.FormatMacAddress(bytes));
    }
}
