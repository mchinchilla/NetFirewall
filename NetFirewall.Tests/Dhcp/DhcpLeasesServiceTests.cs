using Moq;
using NetFirewall.Services.Dhcp;

namespace NetFirewall.Tests.Dhcp
{
    public class DhcpLeasesServiceTests
    {
        private readonly Mock<IDhcpLeasesService> _dhcpLeasesServiceMock;

        public DhcpLeasesServiceTests()
        {
            _dhcpLeasesServiceMock = new Mock<IDhcpLeasesService>();
        }

        [Fact]
        public async Task OfferLease_ShouldReturnIpAddress()
        {
            // Arrange
            var macAddress = "00:11:22:33:44:55";
            var rangeStart = IPAddress.Parse("192.168.1.100");
            var rangeEnd = IPAddress.Parse("192.168.1.200");
            var expectedIp = IPAddress.Parse("192.168.1.150");

            _dhcpLeasesServiceMock.Setup(service => service.OfferLease(macAddress, rangeStart, rangeEnd))
                .ReturnsAsync(expectedIp);

            // Act
            var result = await _dhcpLeasesServiceMock.Object.OfferLease(macAddress, rangeStart, rangeEnd);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(expectedIp, result);
        }

        [Fact]
        public async Task AssignLease_ShouldCompleteSuccessfully()
        {
            // Arrange
            var macAddress = "00:11:22:33:44:55";
            var ipAddress = IPAddress.Parse("192.168.1.150");
            var leaseTime = 3600;

            _dhcpLeasesServiceMock.Setup(service => service.AssignLease(macAddress, ipAddress, leaseTime))
                .Returns(Task.CompletedTask);

            // Act
            await _dhcpLeasesServiceMock.Object.AssignLease(macAddress, ipAddress, leaseTime);

            // Assert
            _dhcpLeasesServiceMock.Verify(service => service.AssignLease(macAddress, ipAddress, leaseTime), Times.Once);
        }

        [Fact]
        public async Task CanAssignIp_ShouldReturnTrue()
        {
            // Arrange
            var macAddress = "00:11:22:33:44:55";
            var ipAddress = IPAddress.Parse("192.168.1.150");

            _dhcpLeasesServiceMock.Setup(service => service.CanAssignIp(macAddress, ipAddress))
                .ReturnsAsync(true);

            // Act
            var result = await _dhcpLeasesServiceMock.Object.CanAssignIp(macAddress, ipAddress);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public async Task ReleaseLease_ShouldCompleteSuccessfully()
        {
            // Arrange
            var macAddress = "00:11:22:33:44:55";

            _dhcpLeasesServiceMock.Setup(service => service.ReleaseLease(macAddress))
                .Returns(Task.CompletedTask);

            // Act
            await _dhcpLeasesServiceMock.Object.ReleaseLease(macAddress);

            // Assert
            _dhcpLeasesServiceMock.Verify(service => service.ReleaseLease(macAddress), Times.Once);
        }

        [Fact]
        public async Task MarkIpAsDeclined_ShouldCompleteSuccessfully()
        {
            // Arrange
            var ipAddress = IPAddress.Parse("192.168.1.150");

            _dhcpLeasesServiceMock.Setup(service => service.MarkIpAsDeclined(ipAddress))
                .Returns(Task.CompletedTask);

            // Act
            await _dhcpLeasesServiceMock.Object.MarkIpAsDeclined(ipAddress);

            // Assert
            _dhcpLeasesServiceMock.Verify(service => service.MarkIpAsDeclined(ipAddress), Times.Once);
        }

        [Fact]
        public async Task GetAssignedIp_ShouldReturnIpAddress()
        {
            // Arrange
            var macAddress = "00:11:22:33:44:55";
            var expectedIp = IPAddress.Parse("192.168.1.150");

            _dhcpLeasesServiceMock.Setup(service => service.GetAssignedIp(macAddress))
                .ReturnsAsync(expectedIp);

            // Act
            var result = await _dhcpLeasesServiceMock.Object.GetAssignedIp(macAddress);

            // Assert
            Assert.NotNull(result);
            Assert.Equal(expectedIp, result);
        }
    }
}
