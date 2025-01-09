using System.Net;
using System.Threading.Tasks;
using Moq;
using Xunit;

namespace NetFirewall.Services.Dhcp.Tests
{
    public class DhcpLeasesServiceTests
    {
        private readonly Mock<IDhcpLeasesService> _dhcpLeasesServiceMock;

        public DhcpLeasesServiceTests()
        {
            _dhcpLeasesServiceMock = new Mock<IDhcpLeasesService>();
        }

        [Fact]
        public async Task OfferLeaseAsync_ShouldReturnIpAddress()
        {
            // Arrange
            var macAddress = "00:11:22:33:44:55";
            var rangeStart = IPAddress.Parse("192.168.1.100");
            var rangeEnd = IPAddress.Parse("192.168.1.200");
            var expectedIpAddress = IPAddress.Parse("192.168.1.101");

            _dhcpLeasesServiceMock
                .Setup(service => service.OfferLeaseAsync(macAddress, rangeStart, rangeEnd))
                .ReturnsAsync(expectedIpAddress);

            // Act
            var result = await _dhcpLeasesServiceMock.Object.OfferLeaseAsync(macAddress, rangeStart, rangeEnd);

            // Assert
            Assert.Equal(expectedIpAddress, result);
        }

        [Fact]
        public async Task AssignLeaseAsync_ShouldCompleteSuccessfully()
        {
            // Arrange
            var macAddress = "00:11:22:33:44:55";
            var ipAddress = IPAddress.Parse("192.168.1.101");
            var leaseTime = 3600;

            _dhcpLeasesServiceMock
                .Setup(service => service.AssignLeaseAsync(macAddress, ipAddress, leaseTime))
                .Returns(Task.CompletedTask);

            // Act
            await _dhcpLeasesServiceMock.Object.AssignLeaseAsync(macAddress, ipAddress, leaseTime);

            // Assert
            _dhcpLeasesServiceMock.Verify(service => service.AssignLeaseAsync(macAddress, ipAddress, leaseTime), Times.Once);
        }

        [Fact]
        public async Task CanAssignIpAsync_ShouldReturnTrue()
        {
            // Arrange
            var macAddress = "00:11:22:33:44:55";
            var ipAddress = IPAddress.Parse("192.168.1.101");

            _dhcpLeasesServiceMock
                .Setup(service => service.CanAssignIpAsync(macAddress, ipAddress))
                .ReturnsAsync(true);

            // Act
            var result = await _dhcpLeasesServiceMock.Object.CanAssignIpAsync(macAddress, ipAddress);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public async Task ReleaseLeaseAsync_ShouldCompleteSuccessfully()
        {
            // Arrange
            var macAddress = "00:11:22:33:44:55";

            _dhcpLeasesServiceMock
                .Setup(service => service.ReleaseLeaseAsync(macAddress))
                .Returns(Task.CompletedTask);

            // Act
            await _dhcpLeasesServiceMock.Object.ReleaseLeaseAsync(macAddress);

            // Assert
            _dhcpLeasesServiceMock.Verify(service => service.ReleaseLeaseAsync(macAddress), Times.Once);
        }

        [Fact]
        public async Task MarkIpAsDeclinedAsync_ShouldCompleteSuccessfully()
        {
            // Arrange
            var ipAddress = IPAddress.Parse("192.168.1.101");

            _dhcpLeasesServiceMock
                .Setup(service => service.MarkIpAsDeclinedAsync(ipAddress))
                .Returns(Task.CompletedTask);

            // Act
            await _dhcpLeasesServiceMock.Object.MarkIpAsDeclinedAsync(ipAddress);

            // Assert
            _dhcpLeasesServiceMock.Verify(service => service.MarkIpAsDeclinedAsync(ipAddress), Times.Once);
        }

        [Fact]
        public async Task GetAssignedIpAsync_ShouldReturnIpAddress()
        {
            // Arrange
            var macAddress = "00:11:22:33:44:55";
            var expectedIpAddress = IPAddress.Parse("192.168.1.101");

            _dhcpLeasesServiceMock
                .Setup(service => service.GetAssignedIpAsync(macAddress))
                .ReturnsAsync(expectedIpAddress);

            // Act
            var result = await _dhcpLeasesServiceMock.Object.GetAssignedIpAsync(macAddress);

            // Assert
            Assert.Equal(expectedIpAddress, result);
        }
    }
}
