using System.Net;
using NetFirewall.DhcpServer;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Pure coverage of <see cref="LinuxRawSocket.TryExtractDhcpPayload"/> — the
/// ethernet/IPv4/UDP demultiplexer on the AF_PACKET receive path. The parser is
/// static, so these run on any OS even though the socket itself is Linux-only.
/// Every rejection branch is attacker-reachable: the frame bytes come straight
/// off the wire.
/// </summary>
public class LinuxRawSocketFrameTests
{
    /// <summary>
    /// Builds an ethernet frame carrying an IPv4/UDP datagram. Defaults form a
    /// valid DHCP-to-port-67 frame; parameters poke individual fields.
    /// </summary>
    private static byte[] BuildFrame(
        byte[]? payload = null,
        int etherType = 0x0800,
        int ipVersion = 4,
        int ihlWords = 5,
        byte protocol = 17,
        int dstPort = 67,
        int srcPort = 68,
        string srcIp = "192.168.1.50",
        int? udpLengthOverride = null,
        int? truncateTo = null)
    {
        payload ??= new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
        var ipHeaderLen = ihlWords * 4;
        var udpLength = udpLengthOverride ?? (8 + payload.Length);
        var frame = new byte[14 + ipHeaderLen + 8 + payload.Length];

        // Ethernet: dst MAC, src MAC, ethertype
        frame[6] = 0xAA; frame[7] = 0xBB; frame[8] = 0xCC; frame[9] = 0x01; frame[10] = 0x02; frame[11] = 0x03;
        frame[12] = (byte)(etherType >> 8);
        frame[13] = (byte)(etherType & 0xFF);

        // IP header
        frame[14] = (byte)((ipVersion << 4) | ihlWords);
        frame[14 + 9] = protocol;
        IPAddress.Parse(srcIp).GetAddressBytes().CopyTo(frame, 14 + 12);
        IPAddress.Parse("255.255.255.255").GetAddressBytes().CopyTo(frame, 14 + 16);

        // UDP header
        var udpOffset = 14 + ipHeaderLen;
        frame[udpOffset] = (byte)(srcPort >> 8);
        frame[udpOffset + 1] = (byte)(srcPort & 0xFF);
        frame[udpOffset + 2] = (byte)(dstPort >> 8);
        frame[udpOffset + 3] = (byte)(dstPort & 0xFF);
        frame[udpOffset + 4] = (byte)(udpLength >> 8);
        frame[udpOffset + 5] = (byte)(udpLength & 0xFF);

        payload.CopyTo(frame, udpOffset + 8);

        return truncateTo.HasValue ? frame[..truncateTo.Value] : frame;
    }

    [Fact]
    public void ValidDhcpFrame_ExtractsPayloadOffsetLengthAndSource()
    {
        var payload = new byte[] { 1, 2, 3, 4, 5, 6 };
        var frame = BuildFrame(payload);

        Assert.True(LinuxRawSocket.TryExtractDhcpPayload(frame, out var info));
        Assert.Equal(14 + 20 + 8, info.PayloadOffset);
        Assert.Equal(payload.Length, info.PayloadLength);
        Assert.Equal(IPAddress.Parse("192.168.1.50"), info.SourceIp);
        Assert.Equal(68, info.SourcePort);
        Assert.Equal(payload, frame.AsSpan(info.PayloadOffset, info.PayloadLength).ToArray());
    }

    [Fact]
    public void IpHeaderWithOptions_Ihl24Bytes_PayloadOffsetShifts()
    {
        // IHL = 6 words (24 bytes) — options present. The UDP header moves.
        var payload = new byte[] { 9, 9, 9 };
        var frame = BuildFrame(payload, ihlWords: 6);

        Assert.True(LinuxRawSocket.TryExtractDhcpPayload(frame, out var info));
        Assert.Equal(14 + 24 + 8, info.PayloadOffset);
        Assert.Equal(payload, frame.AsSpan(info.PayloadOffset, info.PayloadLength).ToArray());
    }

    [Fact]
    public void ArpFrame_Rejected() =>
        Assert.False(LinuxRawSocket.TryExtractDhcpPayload(BuildFrame(etherType: 0x0806), out _));

    [Fact]
    public void Ipv6EtherType_Rejected() =>
        Assert.False(LinuxRawSocket.TryExtractDhcpPayload(BuildFrame(etherType: 0x86DD), out _));

    [Fact]
    public void IpVersion6InHeader_Rejected() =>
        Assert.False(LinuxRawSocket.TryExtractDhcpPayload(BuildFrame(ipVersion: 6), out _));

    [Fact]
    public void MalformedIhl_BelowMinimum_Rejected()
    {
        // IHL = 4 words (16 bytes) is illegal (< 20). Offsets computed from it
        // would land inside the IP header itself.
        Assert.False(LinuxRawSocket.TryExtractDhcpPayload(BuildFrame(ihlWords: 4), out _));
    }

    [Fact]
    public void TcpProtocol_Rejected() =>
        Assert.False(LinuxRawSocket.TryExtractDhcpPayload(BuildFrame(protocol: 6), out _));

    [Fact]
    public void WrongDestinationPort_Rejected() =>
        Assert.False(LinuxRawSocket.TryExtractDhcpPayload(BuildFrame(dstPort: 68), out _));

    [Fact]
    public void UdpLengthClaimsMoreThanFrame_Rejected()
    {
        // Attacker-controlled UDP length field pointing past the frame end —
        // must not be trusted as a read bound.
        Assert.False(LinuxRawSocket.TryExtractDhcpPayload(
            BuildFrame(udpLengthOverride: 8 + 500), out _));
    }

    [Fact]
    public void UdpLengthSmallerThanHeader_Rejected()
    {
        // UDP length < 8 → negative payload length.
        Assert.False(LinuxRawSocket.TryExtractDhcpPayload(BuildFrame(udpLengthOverride: 4), out _));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(10)]   // inside ethernet header
    [InlineData(20)]   // ethernet ok, IP header truncated
    [InlineData(38)]   // IP ok, UDP header truncated
    public void TruncatedFrames_RejectedWithoutThrowing(int length) =>
        Assert.False(LinuxRawSocket.TryExtractDhcpPayload(BuildFrame(truncateTo: length), out _));

    [Fact]
    public void EmptySpan_Rejected() =>
        Assert.False(LinuxRawSocket.TryExtractDhcpPayload(ReadOnlySpan<byte>.Empty, out _));
}
