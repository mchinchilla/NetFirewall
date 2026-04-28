using System.Buffers;
using System.Net;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.DhcpServer;
using NetFirewall.Models.Dhcp;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Edge-case coverage for the DHCP options parser inside <see cref="DhcpWorker"/>.
/// The top-level happy path is already covered by <c>DhcpWorkerParserTests</c>;
/// here we hit the <c>ParseSingleOption</c> switch arms and the
/// <c>ParseDhcpOptions</c> walker boundaries (Pad, End, length-overflow,
/// length-zero, multiple options) — every branch where a malformed packet from
/// a misbehaving client could either crash the worker or silently misroute.
/// </summary>
public class DhcpWorkerOptionsParserTests
{
    private static DhcpWorker CreateWorker()
    {
        var sp = new ServiceCollection().BuildServiceProvider();
        var config = new ConfigurationBuilder().Build();
        return new DhcpWorker(NullLogger<DhcpWorker>.Instance, sp.GetRequiredService<IServiceScopeFactory>(), config);
    }

    private static readonly IPEndPoint AnyEndPoint = new(IPAddress.Loopback, 68);

    /// <summary>
    /// Build a minimal valid BOOTREQUEST whose DHCP options block is exactly
    /// the supplied bytes (caller writes the [code, len, data...] sequence).
    /// <paramref name="optionsSpace"/> sizes the options block — the default of
    /// 336 mirrors a real 576-byte packet, but tests that need to provoke the
    /// "declared length overflows buffer" guard can shrink it.
    /// </summary>
    private static byte[] BuildPacketWithRawOptions(byte[] options, int optionsSpace = 336)
    {
        var pkt = new byte[240 + optionsSpace];
        pkt[0] = 1;             // op = BOOTREQUEST
        pkt[1] = 1; pkt[2] = 6; // htype/hlen
        pkt[4] = 0xDE; pkt[5] = 0xAD; pkt[6] = 0xBE; pkt[7] = 0xEF;
        pkt[28] = 0xAA; pkt[29] = 0xBB; pkt[30] = 0xCC; pkt[31] = 0x00; pkt[32] = 0x00; pkt[33] = 0x01;
        pkt[236] = 99; pkt[237] = 130; pkt[238] = 83; pkt[239] = 99; // magic cookie
        Array.Copy(options, 0, pkt, 240, Math.Min(options.Length, pkt.Length - 240));
        return pkt;
    }

    private static byte[] OptMessageType(DhcpMessageType type) => new byte[] { 53, 1, (byte)type, 0xFF };

    // ── MessageType: every inbound type ────────────────────────────────

    [Theory]
    [InlineData(DhcpMessageType.Discover)]
    [InlineData(DhcpMessageType.Request)]
    [InlineData(DhcpMessageType.Release)]
    [InlineData(DhcpMessageType.Decline)]
    [InlineData(DhcpMessageType.Inform)]
    public void Option53_AllInboundMessageTypes_PopulatedOnRequest(DhcpMessageType type)
    {
        var pkt = BuildPacketWithRawOptions(OptMessageType(type));

        Assert.True(CreateWorker().TryParseDhcpRequest(pkt, AnyEndPoint, out var req));
        Assert.Equal(type, req.MessageType);
    }

    // ── Option 51: IPAddressLeaseTime (4 bytes, network byte order) ────

    [Fact]
    public void Option51_LeaseTime_ParsedFromNetworkByteOrder()
    {
        // 86400 (24h) as big-endian 4-byte int = 0x00 0x01 0x51 0x80
        var opts = new byte[] {
            53, 1, (byte)DhcpMessageType.Request,
            51, 4, 0x00, 0x01, 0x51, 0x80,
            0xFF
        };
        var pkt = BuildPacketWithRawOptions(opts);

        Assert.True(CreateWorker().TryParseDhcpRequest(pkt, AnyEndPoint, out var req));
        Assert.Equal(86400, req.LeaseTime);
    }

    [Fact]
    public void Option51_LeaseTime_ShorterThanFourBytes_Ignored_NotCrash()
    {
        // 3 bytes — parser's `when data.Length >= 4` guard rejects this without
        // crashing on a partial read. LeaseTime stays at its default (0).
        var opts = new byte[] {
            53, 1, (byte)DhcpMessageType.Request,
            51, 3, 0x00, 0x00, 0x05,
            0xFF
        };
        var pkt = BuildPacketWithRawOptions(opts);

        Assert.True(CreateWorker().TryParseDhcpRequest(pkt, AnyEndPoint, out var req));
        Assert.Equal(0, req.LeaseTime);
    }

    // ── Option 55: ParameterRequestList ────────────────────────────────

    [Fact]
    public void Option55_ParameterRequestList_PassedThroughVerbatim()
    {
        // Common request list: 1 (subnet mask), 3 (router), 6 (DNS), 15 (domain name)
        var prl = new byte[] { 1, 3, 6, 15 };
        var opts = new byte[] {
            53, 1, (byte)DhcpMessageType.Discover,
            55, (byte)prl.Length, prl[0], prl[1], prl[2], prl[3],
            0xFF
        };
        var pkt = BuildPacketWithRawOptions(opts);

        Assert.True(CreateWorker().TryParseDhcpRequest(pkt, AnyEndPoint, out var req));
        Assert.Equal(prl, req.ParameterRequestList);
    }

    // ── Option 60: VendorClassIdentifier + IsPxeRequest detection ──────

    [Fact]
    public void Option60_VendorClassIdentifier_PXEClient_TrigersIsPxeRequest()
    {
        var vci = "PXEClient:Arch:00000:UNDI:002001"u8.ToArray();
        var opts = new List<byte>
        {
            53, 1, (byte)DhcpMessageType.Discover,
            60, (byte)vci.Length
        };
        opts.AddRange(vci);
        opts.Add(0xFF);
        var pkt = BuildPacketWithRawOptions(opts.ToArray());

        Assert.True(CreateWorker().TryParseDhcpRequest(pkt, AnyEndPoint, out var req));
        Assert.Contains("PXEClient", req.VendorClassIdentifier);
        Assert.True(req.IsPxeRequest);
    }

    [Fact]
    public void Option60_VendorClassIdentifier_NonPxe_IsPxeRequestStaysFalse()
    {
        var vci = "MSFT 5.0"u8.ToArray();
        var opts = new List<byte>
        {
            53, 1, (byte)DhcpMessageType.Discover,
            60, (byte)vci.Length
        };
        opts.AddRange(vci);
        opts.Add(0xFF);
        var pkt = BuildPacketWithRawOptions(opts.ToArray());

        Assert.True(CreateWorker().TryParseDhcpRequest(pkt, AnyEndPoint, out var req));
        Assert.Equal("MSFT 5.0", req.VendorClassIdentifier);
        Assert.False(req.IsPxeRequest);
    }

    // ── Option 61: ClientIdentifier ────────────────────────────────────

    [Fact]
    public void Option61_ClientIdentifier_PassedThroughAsBytes()
    {
        // Common shape: type (01 = ethernet) + 6-byte MAC.
        var cid = new byte[] { 0x01, 0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33 };
        var opts = new List<byte>
        {
            53, 1, (byte)DhcpMessageType.Request,
            61, (byte)cid.Length
        };
        opts.AddRange(cid);
        opts.Add(0xFF);
        var pkt = BuildPacketWithRawOptions(opts.ToArray());

        Assert.True(CreateWorker().TryParseDhcpRequest(pkt, AnyEndPoint, out var req));
        Assert.Equal(cid, req.ClientIdentifier);
    }

    // ── Pad / End / multi-option boundaries ────────────────────────────

    [Fact]
    public void OptionWalker_PadByte_SkippedWithoutConsumingLength()
    {
        // Pad (0x00) has no length/data — the walker must skip it and continue.
        // Layout: Pad, Pad, MessageType=Request, Pad, End.
        var opts = new byte[] {
            0, 0,
            53, 1, (byte)DhcpMessageType.Request,
            0,
            0xFF
        };
        var pkt = BuildPacketWithRawOptions(opts);

        Assert.True(CreateWorker().TryParseDhcpRequest(pkt, AnyEndPoint, out var req));
        Assert.Equal(DhcpMessageType.Request, req.MessageType);
    }

    [Fact]
    public void OptionWalker_StopsAtEndByte_IgnoresAnythingAfter()
    {
        // After 0xFF, we lay down a "fake" Hostname option that would change
        // the request if parsed. Walker must NOT process it.
        var opts = new byte[] {
            53, 1, (byte)DhcpMessageType.Request,
            0xFF,
            12, 5, (byte)'g', (byte)'h', (byte)'o', (byte)'s', (byte)'t'
        };
        var pkt = BuildPacketWithRawOptions(opts);

        Assert.True(CreateWorker().TryParseDhcpRequest(pkt, AnyEndPoint, out var req));
        Assert.Equal(DhcpMessageType.Request, req.MessageType);
        Assert.Null(req.Hostname); // post-End bytes were ignored
    }

    [Fact]
    public void OptionWalker_TruncatedOption_BreaksWithoutCrash()
    {
        // Hostname option declares length 100 but the options buffer only has
        // ~5 bytes left after it — walker must detect the overflow and stop,
        // not throw or read past the buffer. We shrink the options space to
        // exactly fit the malformed option header so the guard actually fires
        // (with the default 336-byte options block, a length-100 option near
        // the start would just read trailing zeros and look "valid").
        var opts = new byte[] {
            53, 1, (byte)DhcpMessageType.Request,
            12, 100, (byte)'a', (byte)'b', (byte)'c'
            // declared 100 chars but only 3 follow before the buffer ends
        };
        var pkt = BuildPacketWithRawOptions(opts, optionsSpace: opts.Length);

        // Parser returns true (the BOOTP fixed header is intact); the Hostname
        // is dropped because the walker bails on the overflow check. No throw.
        Assert.True(CreateWorker().TryParseDhcpRequest(pkt, AnyEndPoint, out var req));
        Assert.Equal(DhcpMessageType.Request, req.MessageType);
        Assert.Null(req.Hostname);
    }

    [Fact]
    public void OptionWalker_LengthByteAtBufferEnd_HandledGracefully()
    {
        // Code byte at the end of available options space, no length byte after.
        // The walker's `if (i >= optionsSpan.Length) break` guards this.
        var opts = new byte[] {
            53, 1, (byte)DhcpMessageType.Discover,
            12 // dangling option code, no length byte to follow
        };
        var pkt = BuildPacketWithRawOptions(opts);

        Assert.True(CreateWorker().TryParseDhcpRequest(pkt, AnyEndPoint, out var req));
        Assert.Equal(DhcpMessageType.Discover, req.MessageType);
    }

    [Fact]
    public void OptionWalker_MultipleOptionsInSequence_AllParsed()
    {
        // Realistic DISCOVER from a typical client.
        var opts = new List<byte>
        {
            53, 1, (byte)DhcpMessageType.Discover,
            61, 7, 0x01, 0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33,
            12, 6, (byte)'l', (byte)'a', (byte)'p', (byte)'t', (byte)'o', (byte)'p',
            55, 4, 1, 3, 6, 15,
            50, 4, 192, 168, 1, 100,
            0xFF
        };
        var pkt = BuildPacketWithRawOptions(opts.ToArray());

        Assert.True(CreateWorker().TryParseDhcpRequest(pkt, AnyEndPoint, out var req));
        Assert.Equal(DhcpMessageType.Discover, req.MessageType);
        Assert.NotNull(req.ClientIdentifier);
        Assert.Equal("laptop", req.Hostname);
        Assert.Equal(new byte[] { 1, 3, 6, 15 }, req.ParameterRequestList);
        Assert.Equal("192.168.1.100", req.RequestedIp.ToString());
    }

    [Fact]
    public void OptionWalker_LengthZeroData_HandledByGuards()
    {
        // Option with declared length 0 — the `when data.Length > 0` guards
        // in the switch cause those types to be silently skipped (defaults stay).
        var opts = new byte[] {
            53, 1, (byte)DhcpMessageType.Request,
            12, 0,                 // empty Hostname → ignored by guard
            60, 0,                 // empty VendorClass → ignored by guard
            0xFF
        };
        var pkt = BuildPacketWithRawOptions(opts);

        Assert.True(CreateWorker().TryParseDhcpRequest(pkt, AnyEndPoint, out var req));
        Assert.Equal(DhcpMessageType.Request, req.MessageType);
        Assert.Null(req.Hostname);
        Assert.Null(req.VendorClassIdentifier);
        Assert.False(req.IsPxeRequest); // depends on VendorClassIdentifier; null = false
    }

    // ── DhcpPacketContext: ArrayPool return on Dispose ─────────────────

    [Fact]
    public void DhcpPacketContext_Dispose_ReturnsBufferToPool()
    {
        // Use a tracking pool so we can assert Return was called with our buffer.
        var pool = new TrackingArrayPool();
        var buf = pool.Rent(576);

        using (var ctx = new DhcpPacketContext(buf, length: 300,
            remoteEndPoint: new IPEndPoint(IPAddress.Loopback, 68),
            interfaceName: "eth0",
            pool: pool))
        {
            Assert.Same(buf, ctx.Buffer);
            Assert.Equal(300, ctx.Length);
            Assert.Equal("eth0", ctx.InterfaceName);
        }
        // Dispose ran when the using exited.
        Assert.Single(pool.Returned);
        Assert.Same(buf, pool.Returned[0]);
    }

    [Fact]
    public void DhcpPacketContext_NullInterfaceName_AllowedForWindowsPath()
    {
        // The Windows UDP path doesn't carry an interface name; the field is
        // nullable on purpose — pin that the constructor accepts null.
        // Use a TrackingArrayPool so Dispose can return the buffer (Shared
        // would reject any array it didn't rent itself).
        var pool = new TrackingArrayPool();
        using var ctx = new DhcpPacketContext(
            pool.Rent(10), length: 10,
            remoteEndPoint: new IPEndPoint(IPAddress.Loopback, 68),
            interfaceName: null,
            pool: pool);

        Assert.Null(ctx.InterfaceName);
    }

    /// <summary>ArrayPool that records every Return so tests can assert on it.</summary>
    private sealed class TrackingArrayPool : ArrayPool<byte>
    {
        public List<byte[]> Returned { get; } = new();
        public override byte[] Rent(int minimumLength) => new byte[minimumLength];
        public override void Return(byte[] array, bool clearArray = false) => Returned.Add(array);
    }
}
