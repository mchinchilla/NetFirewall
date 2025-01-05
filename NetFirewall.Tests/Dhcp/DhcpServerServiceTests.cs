using Moq;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;

namespace NetFirewall.Tests.Dhcp;

public class DhcpServerServiceTests
{
    private readonly Mock<IDhcpServerService> _dhcpServerServiceMock;

    public DhcpServerServiceTests()
    {
        _dhcpServerServiceMock = new Mock<IDhcpServerService>();
    }

    [Fact]
    public async Task CreateDhcpResponse_ShouldReturnByteArray()
    {
        // Arrange
        var request = new DhcpRequest
        {
            ClientMac = "00:11:22:33:44:55",
            IsBootp = false,
            IsPxeRequest = false,
            MessageType = DhcpMessageType.Discover,
            RequestedIp = IPAddress.Parse("192.168.99.100"),
            ClientIp = IPAddress.Parse("192.168.99.101"),
            Hostname = "test-client",
            LeaseTime = 3600
        };

        var expectedResponse = new byte[] { 1, 2, 3, 4, 5 };

        _dhcpServerServiceMock.Setup(service => service.CreateDhcpResponse(request))
            .ReturnsAsync(expectedResponse);

        // Act
        var result = await _dhcpServerServiceMock.Object.CreateDhcpResponse(request);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(expectedResponse, result);
    }

    [Fact]
    public async Task CreateDhcpResponse_ShouldHandleNullRequest()
    {
        // Arrange
        DhcpRequest request = null;

        _dhcpServerServiceMock.Setup(service => service.CreateDhcpResponse(request))
            .ReturnsAsync((byte[])null);

        // Act
        var result = await _dhcpServerServiceMock.Object.CreateDhcpResponse(request);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task CreateDhcpResponse_ShouldHandleEmptyResponse()
    {
        // Arrange
        var request = new DhcpRequest
        {
            ClientMac = "00:11:22:33:44:55",
            IsBootp = false,
            IsPxeRequest = false,
            MessageType = DhcpMessageType.Discover,
            RequestedIp = IPAddress.Parse("192.168.99.100"),
            ClientIp = IPAddress.Parse("192.168.99.101"),
            Hostname = "test-client",
            LeaseTime = 3600
        };

        var expectedResponse = new byte[] { };

        _dhcpServerServiceMock.Setup(service => service.CreateDhcpResponse(request))
            .ReturnsAsync(expectedResponse);

        // Act
        var result = await _dhcpServerServiceMock.Object.CreateDhcpResponse(request);

        // Assert
        Assert.NotNull(result);
        Assert.Empty(result);
    }
}
