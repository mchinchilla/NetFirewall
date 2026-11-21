using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// 2026-11 DHCP gaps: the parameter request list (55) and max message size (57) are honoured,
/// a reservation's own lease time wins, and ARM64 / UEFI HTTP boot clients get their own file.
/// </summary>
public sealed class DhcpPrlSizeAndBootTests
{
    private const string Mac = "aa:bb:cc:00:00:01";
    private static readonly IPAddress Offered = IPAddress.Parse("192.168.50.120");

    private static DhcpSubnet Subnet() => new()
    {
        Id = Guid.NewGuid(), Name = "LAN", Network = "192.168.50.0/24", SubnetMask = IPAddress.Parse("255.255.255.0"),
        Router = IPAddress.Parse("192.168.50.1"), Broadcast = IPAddress.Parse("192.168.50.255"),
        DnsServers = [IPAddress.Parse("192.168.50.1")], NtpServers = [IPAddress.Parse("192.168.50.1")],
        DomainName = "home.lan", DefaultLeaseTime = 3600, InterfaceMtu = 1500,
        TftpServer = "192.168.50.1", BootFilename = "pxelinux.0", BootFilenameUefi = "grubx64.efi",
    };

    private static DhcpRequest Discover(byte[]? prl = null) => new()
    {
        ClientMac = Mac, ChAddr = new byte[16], Xid = [1, 2, 3, 4], MessageType = DhcpMessageType.Discover,
        CiAddr = IPAddress.Any, YiAddr = IPAddress.Any, SiAddr = IPAddress.Any, GiAddr = IPAddress.Any,
        Hostname = "laptop", ParameterRequestList = prl,
    };

    private static DhcpServerService Service(DhcpSubnet subnet, IDhcpReservationCache? reservations = null, DhcpClass? cls = null)
    {
        var subnets = new Mock<IDhcpSubnetService>();
        subnets.Setup(x => x.FindSubnetForRequestAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>())).ReturnsAsync(subnet);
        subnets.Setup(x => x.MatchClientClassAsync(It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>())).ReturnsAsync(cls);
        subnets.Setup(x => x.FindAvailableIpInSubnetAsync(subnet, Mac, It.IsAny<DhcpRequest>(), It.IsAny<CancellationToken>()))
               .ReturnsAsync((Offered, null));
        subnets.Setup(x => x.CheckRequestedIpAsync(subnet, Mac, Offered, It.IsAny<CancellationToken>()))
               .ReturnsAsync(RequestedIpVerdict.Allowed);
        var leases = new Mock<IDhcpLeasesService>();
        leases.Setup(l => l.CanAssignIpAsync(Mac, Offered)).ReturnsAsync(true);
        return new DhcpServerService(leases.Object, subnets.Object, NullLogger<DhcpServerService>.Instance,
            Options.Create(new DhcpConfig()), reservations: reservations);
    }

    private static List<byte> Codes(DhcpResponseBuffer r)
    {
        var s = r.Span;
        var codes = new List<byte>();
        for (var i = 240; i < s.Length;)
        {
            if (s[i] == 255) break;
            if (s[i] == 0) { i++; continue; }
            codes.Add(s[i]);
            i += 2 + s[i + 1];
        }
        return codes;
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

    private static int UInt32(byte[] b) => (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];

    // ── Option 55 ──

    [Fact]
    public async Task NoRequestList_SendsEveryConfiguredOption()
    {
        using var r = await Service(Subnet()).CreateDhcpResponseAsync(Discover());
        var codes = Codes(r);
        foreach (var c in new byte[] { 53, 54, 1, 3, 51, 58, 59, 28, 6, 15, 12, 42, 26 })
            Assert.Contains(c, codes);
    }

    [Fact]
    public async Task EmptyRequestList_IsTreatedAsNoList()
    {
        using var r = await Service(Subnet()).CreateDhcpResponseAsync(Discover(prl: []));
        Assert.Contains((byte)42, Codes(r));
    }

    [Fact]
    public async Task RequestList_SendsOnlyWhatWasAsked_PlusTheEssentials()
    {
        using var r = await Service(Subnet()).CreateDhcpResponseAsync(Discover(prl: [1, 3, 6]));
        var codes = Codes(r);
        foreach (var c in new byte[] { 53, 54, 1, 3, 6, 51, 58, 59 })
            Assert.Contains(c, codes);
        foreach (var c in new byte[] { 28, 15, 12, 42, 26 })
            Assert.DoesNotContain(c, codes);
    }

    [Fact]
    public async Task RequestList_WithoutRouterOrMask_StillCarriesThem()
    {
        // A client that only asks for DNS must still get a usable configuration.
        using var r = await Service(Subnet()).CreateDhcpResponseAsync(Discover(prl: [6]));
        var codes = Codes(r);
        Assert.Contains((byte)1, codes);
        Assert.Contains((byte)3, codes);
        Assert.Contains((byte)51, codes);
    }

    [Fact]
    public async Task SkippedBuiltIn_CannotBeSmuggledInByACustomOption()
    {
        // NTP (42) is configured on the subnet but not requested; a custom 42 must not replace it.
        var subnet = Subnet();
        subnet.CustomOptions = [new DhcpCustomOption { OptionCode = 42, OptionValue = [8, 8, 8, 8] }];
        using var r = await Service(subnet).CreateDhcpResponseAsync(Discover(prl: [1, 3, 6]));
        Assert.Null(Option(r, 42));
    }

    [Fact]
    public async Task CustomOptions_AreNotFilteredByTheRequestList()
    {
        // Devices rely on unrequested vendor options (43 for APs); there is no per-option flag yet.
        var subnet = Subnet();
        subnet.CustomOptions = [new DhcpCustomOption { OptionCode = 224, OptionValue = [0xAB] }];
        using var r = await Service(subnet).CreateDhcpResponseAsync(Discover(prl: [1, 3, 6]));
        Assert.Equal([0xAB], Option(r, 224));
    }

    // ── Option 57 ──

    [Fact]
    public void ReplyLimit_Defaults_To548_AndHonoursOption57()
    {
        Assert.Equal(548, DhcpServerService.ReplyLimit(new DhcpRequest(), 1024));
        Assert.Equal(548, DhcpServerService.ReplyLimit(new DhcpRequest { MaxMessageSize = 300 }, 1024));   // below the legal 576
        Assert.Equal(1472, DhcpServerService.ReplyLimit(new DhcpRequest { MaxMessageSize = 1500 }, 2048));
        Assert.Equal(1024, DhcpServerService.ReplyLimit(new DhcpRequest { MaxMessageSize = 1500 }, 1024)); // buffer cap
    }

    [Fact]
    public async Task OversizedCustomOptions_AreDropped_ToFitTheClientsLimit_EssentialsKept()
    {
        var subnet = Subnet();
        subnet.CustomOptions = [
            new DhcpCustomOption { OptionCode = 224, OptionValue = new byte[200] },
            new DhcpCustomOption { OptionCode = 225, OptionValue = new byte[200] },
        ];

        using var small = await Service(subnet).CreateDhcpResponseAsync(Discover());
        Assert.True(small.Length <= 548, $"reply is {small.Length} bytes");
        Assert.NotNull(Option(small, 51));
        Assert.NotNull(Option(small, 3));
        Assert.False(Option(small, 224) is not null && Option(small, 225) is not null);

        var big = Discover();
        big.MaxMessageSize = 1500;
        using var large = await Service(subnet).CreateDhcpResponseAsync(big);
        Assert.NotNull(Option(large, 224));
        Assert.NotNull(Option(large, 225));
    }

    [Fact]
    public async Task UnderSizePressure_RequestedCustomOptionsGoFirst()
    {
        var subnet = Subnet();
        subnet.CustomOptions = [
            new DhcpCustomOption { OptionCode = 224, OptionValue = new byte[200] },   // not requested
            new DhcpCustomOption { OptionCode = 225, OptionValue = new byte[200] },   // requested
        ];
        using var r = await Service(subnet).CreateDhcpResponseAsync(Discover(prl: [1, 3, 6, 225]));
        Assert.NotNull(Option(r, 225));
        Assert.Null(Option(r, 224));
    }

    // ── Per-host lease time ──

    [Fact]
    public async Task ReservationLeaseTime_WinsOverTheSubnetDefault_InOfferAndAck()
    {
        var reservations = new Mock<IDhcpReservationCache>();
        reservations.Setup(x => x.GetLeaseTimeAsync(Mac, It.IsAny<CancellationToken>())).ReturnsAsync(604800);
        var subnet = Subnet();
        var svc = Service(subnet, reservations.Object);

        using var offer = await svc.CreateDhcpResponseAsync(Discover());
        Assert.Equal(604800, UInt32(Option(offer, 51)!));
        Assert.Equal(302400, UInt32(Option(offer, 58)!));

        var request = Discover();
        request.MessageType = DhcpMessageType.Request;
        request.RequestedIp = Offered;
        using var ack = await svc.CreateDhcpResponseAsync(request);
        Assert.Equal(604800, UInt32(Option(ack, 51)!));
    }

    [Fact]
    public async Task NoReservationLeaseTime_UsesTheSubnetDefault()
    {
        var reservations = new Mock<IDhcpReservationCache>();
        reservations.Setup(x => x.GetLeaseTimeAsync(Mac, It.IsAny<CancellationToken>())).ReturnsAsync((int?)null);
        using var offer = await Service(Subnet(), reservations.Object).CreateDhcpResponseAsync(Discover());
        Assert.Equal(3600, UInt32(Option(offer, 51)!));
    }

    // ── ARM64 / HTTP boot ──

    private static DhcpRequest Pxe(ushort arch) => new()
    {
        IsPxeRequest = true, ClientArchitecture = arch, VendorClassIdentifier = $"PXEClient:Arch:{arch:D5}:UNDI:003016",
    };

    [Theory]
    [InlineData(PxeBoot.BiosX86, "pxelinux.0")]
    [InlineData(PxeBoot.EfiX64Bc, "grubx64.efi")]
    [InlineData(PxeBoot.EfiArm64, "grubaa64.efi")]
    [InlineData(PxeBoot.EfiArm32, "grubx64.efi")]   // no ARM32 field: the UEFI file, as before
    public void BootFile_ByArchitecture(ushort arch, string expected)
    {
        var subnet = Subnet();
        subnet.BootFilenameArm64 = "grubaa64.efi";
        Assert.Equal(expected, PxeBoot.BootFile(Pxe(arch), subnet, null));
    }

    [Fact]
    public void BootFile_Arm64WithoutItsOwnFile_FallsBackToUefi() =>
        Assert.Equal("grubx64.efi", PxeBoot.BootFile(Pxe(PxeBoot.EfiArm64), Subnet(), null));

    [Fact]
    public void BootFile_HttpClient_GetsTheUri_OrNothing()
    {
        var http = new DhcpRequest { IsHttpBoot = true, ClientArchitecture = PxeBoot.HttpX64, VendorClassIdentifier = "HTTPClient:Arch:00016:UNDI:003001" };
        var subnet = Subnet();
        Assert.Null(PxeBoot.BootFile(http, subnet, null));                       // never a TFTP file name
        subnet.BootFilenameHttp = "http://192.168.50.1/boot/grubx64.efi";
        Assert.Equal("http://192.168.50.1/boot/grubx64.efi", PxeBoot.BootFile(http, subnet, null));
    }

    [Fact]
    public async Task HttpBootOffer_SaysHttpClient_CarriesTheUriInOption67_NoPxeDiscovery()
    {
        var subnet = Subnet();
        var uri = "http://192.168.50.1/boot/" + new string('x', 140) + ".efi";   // longer than the 128-byte file field
        subnet.BootFilenameHttp = uri;
        var request = Discover();
        request.IsHttpBoot = true;
        request.VendorClassIdentifier = "HTTPClient:Arch:00016:UNDI:003001";
        request.ClientArchitecture = PxeBoot.HttpX64;

        using var r = await Service(subnet).CreateDhcpResponseAsync(request);

        Assert.Equal("HTTPClient"u8.ToArray(), Option(r, 60));
        Assert.Equal(System.Text.Encoding.ASCII.GetBytes(uri), Option(r, 67));
        Assert.Null(Option(r, 43));
        Assert.Null(Option(r, 66));
        Assert.Equal(0, r.Span[108]);   // the URI is not truncated into the file field
    }

    [Fact]
    public async Task HttpBootClient_WithoutAUri_GetsAPlainOffer()
    {
        var request = Discover();
        request.IsHttpBoot = true;
        request.VendorClassIdentifier = "HTTPClient:Arch:00016:UNDI:003001";
        using var r = await Service(Subnet()).CreateDhcpResponseAsync(request);
        Assert.Null(Option(r, 60));
        Assert.Null(Option(r, 67));
        Assert.Equal((byte)DhcpMessageType.Offer, Option(r, 53)![0]);
    }

    [Theory]
    [InlineData("http://10.0.0.1/boot.efi", true)]
    [InlineData("https://boot.example.com/x64/grub.efi", true)]
    [InlineData("tftp://10.0.0.1/boot.efi", false)]
    [InlineData("grubx64.efi", false)]
    public void IsHttpUri(string text, bool expected) => Assert.Equal(expected, PxeBoot.IsHttpUri(text));
}
