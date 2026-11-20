using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using NetFirewall.DhcpServer;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>The 🟡 findings of the 2026-11 review: NAK shape, RELEASE scope, client-id echo, padding, PXE, raw-socket filter.</summary>
public sealed class DhcpMinorFixesTests
{
    private const string Mac = "aa:bb:cc:00:00:01";
    private readonly Mock<IDhcpLeasesService> _leases = new(MockBehavior.Strict);
    private readonly Mock<IDhcpSubnetService> _subnets = new(MockBehavior.Strict);

    private static readonly DhcpSubnet Lan = new()
    {
        Id = Guid.NewGuid(), Name = "LAN", Network = "192.168.50.0/24",
        SubnetMask = IPAddress.Parse("255.255.255.0"), Router = IPAddress.Parse("192.168.50.1"), DefaultLeaseTime = 3600,
        TftpServer = "192.168.50.5", BootFilename = "undionly.kpxe", BootFilenameUefi = "ipxe.efi",
        BootFilenameIpxe = "http://192.168.50.5/boot.ipxe",
    };

    private DhcpServerService Svc() => new(_leases.Object, _subnets.Object, NullLogger<DhcpServerService>.Instance,
        Options.Create(new DhcpConfig
        {
            ServerIp = IPAddress.Parse("10.0.0.1"), IpRangeStart = IPAddress.Parse("10.0.0.100"),
            IpRangeEnd = IPAddress.Parse("10.0.0.200"), SubnetMask = IPAddress.Parse("255.255.255.0"),
            Gateway = IPAddress.Parse("10.0.0.1"), DnsServers = [IPAddress.Parse("8.8.8.8")], LeaseTime = 3600,
        }));

    private static DhcpRequest Req(DhcpMessageType type) => new()
    {
        ClientMac = Mac, ChAddr = [0xAA, 0xBB, 0xCC, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], Xid = [1, 2, 3, 4],
        CiAddr = IPAddress.Any, YiAddr = IPAddress.Any, SiAddr = IPAddress.Any, GiAddr = IPAddress.Any, MessageType = type,
    };

    private void OnLan()
    {
        _subnets.Setup(x => x.FindSubnetForRequestAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>())).ReturnsAsync(Lan);
        _subnets.Setup(x => x.MatchClientClassAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>())).ReturnsAsync((DhcpClass?)null);
    }

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

    // ── NAK shape (RFC 2131 Table 3 / §4.3.2) ──

    [Fact]
    public async Task Nak_ThroughARelay_SetsBroadcast_AndZeroesCiaddrSiaddrAndFile()
    {
        OnLan();
        var req = Req(DhcpMessageType.Request);
        req.GiAddr = IPAddress.Parse("192.168.50.254");
        req.CiAddr = IPAddress.Parse("192.168.50.77");
        req.RequestedIp = IPAddress.Parse("172.16.0.9");
        _subnets.Setup(x => x.CheckRequestedIpAsync(Lan, Mac, req.RequestedIp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(RequestedIpVerdict.WrongNetwork);

        using var r = await Svc().CreateDhcpResponseAsync(req);
        var s = r.Span;

        Assert.Equal((byte)DhcpMessageType.Nak, Option(r, 53)![0]);
        Assert.Equal(0x80, s[10] & 0x80);                       // broadcast bit
        Assert.True(s.Slice(12, 4).ToArray().All(b => b == 0)); // ciaddr
        Assert.True(s.Slice(20, 4).ToArray().All(b => b == 0)); // siaddr
        Assert.True(s.Slice(108, 128).ToArray().All(b => b == 0)); // file
    }

    [Fact]
    public async Task EveryReply_IsAtLeast300Bytes()
    {
        OnLan();
        var req = Req(DhcpMessageType.Request);
        req.RequestedIp = IPAddress.Parse("172.16.0.9");
        _subnets.Setup(x => x.CheckRequestedIpAsync(Lan, Mac, req.RequestedIp, It.IsAny<CancellationToken>()))
            .ReturnsAsync(RequestedIpVerdict.WrongNetwork);

        using var r = await Svc().CreateDhcpResponseAsync(req);   // a NAK, the smallest reply
        Assert.True(r.Length >= 300, $"reply was {r.Length} bytes");
    }

    // ── client-id echo (RFC 6842) ──

    [Fact]
    public async Task ClientIdentifier_IsEchoed()
    {
        OnLan();
        _subnets.Setup(x => x.FindAvailableIpInSubnetAsync(Lan, Mac, It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((IPAddress.Parse("192.168.50.120"), null));
        var req = Req(DhcpMessageType.Discover);
        req.ClientIdentifier = [1, 0xAA, 0xBB, 0xCC, 0, 0, 1];

        using var r = await Svc().CreateDhcpResponseAsync(req);
        Assert.Equal(req.ClientIdentifier, Option(r, 61));
    }

    // ── RELEASE only frees the client's own lease, only when addressed to us ──

    [Fact]
    public async Task Release_ForADifferentAddressThanTheClientHolds_IsIgnored()
    {
        OnLan();
        _leases.Setup(x => x.GetAssignedIpAsync(Mac)).ReturnsAsync(IPAddress.Parse("192.168.50.120"));
        var req = Req(DhcpMessageType.Release);
        req.CiAddr = IPAddress.Parse("192.168.50.99");

        using var r = await Svc().CreateDhcpResponseAsync(req);
        _leases.Verify(x => x.ReleaseLeaseAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task Release_AddressedToAnotherServer_IsIgnored()
    {
        OnLan();
        var req = Req(DhcpMessageType.Release);
        req.CiAddr = IPAddress.Parse("192.168.50.120");
        req.ServerIdentifier = IPAddress.Parse("192.168.50.250");

        using var r = await Svc().CreateDhcpResponseAsync(req);
        _leases.Verify(x => x.ReleaseLeaseAsync(It.IsAny<string>()), Times.Never);   // strict: never even looked up
    }

    [Fact]
    public async Task Release_OfItsOwnLease_Releases()
    {
        OnLan();
        _leases.Setup(x => x.GetAssignedIpAsync(Mac)).ReturnsAsync(IPAddress.Parse("192.168.50.120"));
        _leases.Setup(x => x.ReleaseLeaseAsync(Mac)).Returns(Task.CompletedTask);
        var req = Req(DhcpMessageType.Release);
        req.CiAddr = IPAddress.Parse("192.168.50.120");

        using var r = await Svc().CreateDhcpResponseAsync(req);
        _leases.Verify(x => x.ReleaseLeaseAsync(Mac), Times.Once);
    }

    // ── PXE / iPXE ──

    [Theory]
    [InlineData((ushort)7, null, "ipxe.efi")]                           // option 93: UEFI x64
    [InlineData((ushort)0, null, "undionly.kpxe")]                      // option 93: BIOS
    [InlineData(null, "PXEClient:Arch:00009:UNDI:003016", "ipxe.efi")]  // arch only in option 60
    [InlineData(null, "PXEClient:Arch:00000:UNDI:002001", "undionly.kpxe")]  // "00007"-free BIOS…
    [InlineData(null, "PXEClient:Arch:00000:UNDI:000007", "undionly.kpxe")]  // …and UNDI "000007" no longer reads as UEFI
    public void BootFile_FollowsTheArchitecture(ushort? arch, string? vendorClass, string expected)
    {
        var req = Req(DhcpMessageType.Discover);
        req.IsPxeRequest = true;
        req.ClientArchitecture = arch;
        req.VendorClassIdentifier = vendorClass ?? "PXEClient";
        Assert.Equal(expected, PxeBoot.BootFile(req, Lan, null));
    }

    [Fact]
    public void BootFile_ForIpxe_IsItsScript_BreakingTheChainloadLoop()
    {
        var req = Req(DhcpMessageType.Discover);
        req.IsPxeRequest = true; req.ClientArchitecture = 7; req.UserClass = "iPXE";
        Assert.Equal("http://192.168.50.5/boot.ipxe", PxeBoot.BootFile(req, Lan, null));
    }

    [Theory]
    [InlineData(new byte[] { 0x69, 0x50, 0x58, 0x45 }, "iPXE")]        // bare string (what iPXE sends)
    [InlineData(new byte[] { 4, 0x69, 0x50, 0x58, 0x45 }, "iPXE")]     // RFC 3004 length-prefixed
    public void UserClass_ParsesBothEncodings(byte[] raw, string expected) => Assert.Equal(expected, PxeBoot.ParseUserClass(raw));

    [Fact]
    public async Task PxeOffer_SaysPxeClient_UsesOption43_AndNeverSends93Or94()
    {
        OnLan();
        _subnets.Setup(x => x.FindAvailableIpInSubnetAsync(Lan, Mac, It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((IPAddress.Parse("192.168.50.120"), null));
        var req = Req(DhcpMessageType.Discover);
        req.IsPxeRequest = true; req.ClientArchitecture = 7; req.VendorClassIdentifier = "PXEClient:Arch:00007:UNDI:003016";
        req.ClientMachineId = [0, .. Enumerable.Range(1, 16).Select(i => (byte)i)];

        using var r = await Svc().CreateDhcpResponseAsync(req);

        Assert.Equal("PXEClient"u8.ToArray(), Option(r, 60));
        Assert.Equal([6, 1, 8, 255], Option(r, 43));
        Assert.Equal(req.ClientMachineId, Option(r, 97));     // echoed UUID, 17 bytes
        Assert.Null(Option(r, 93));
        Assert.Null(Option(r, 94));
        Assert.Equal("ipxe.efi"u8.ToArray(), Option(r, 67));
    }

    // ── raw socket: only packets addressed to us ──

    [Theory]
    [InlineData(0, "255.255.255.255", true)]    // PACKET_HOST broadcast
    [InlineData(1, "255.255.255.255", true)]    // PACKET_BROADCAST
    [InlineData(0, "192.168.50.1", true)]       // relay/renewal unicast to us
    [InlineData(0, "192.168.50.9", false)]      // routed through us to ANOTHER DHCP server
    [InlineData(3, "255.255.255.255", false)]   // PACKET_OTHERHOST (promiscuous NIC)
    [InlineData(4, "255.255.255.255", false)]   // PACKET_OUTGOING (our own reply looped back)
    public void RawSocket_AcceptsOnlyWhatIsOurs(byte packetType, string destination, bool expected) =>
        Assert.Equal(expected, LinuxRawSocket.ShouldAccept(packetType, IPAddress.Parse(destination),
            ip => ip.Equals(IPAddress.Parse("192.168.50.1"))));
}
