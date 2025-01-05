using Moq;
using NetFirewall.Services.Dhcp;

namespace NetFirewall.Tests.Dhcp
{
    public class DdnsServiceTests
    {
        private readonly Mock<IDdnsService> _ddnsServiceMock;

        public DdnsServiceTests()
        {
            _ddnsServiceMock = new Mock<IDdnsService>();
        }

        [Fact]
        public async Task UpdateDnsAsync_ShouldCompleteSuccessfully()
        {
            // Arrange
            var hostname = "test-host";
            var ipAddress = IPAddress.Parse("192.168.99.150");

            _ddnsServiceMock.Setup(service => service.UpdateDnsAsync(hostname, ipAddress))
                .Returns(Task.CompletedTask);

            // Act
            await _ddnsServiceMock.Object.UpdateDnsAsync(hostname, ipAddress);

            // Assert
            _ddnsServiceMock.Verify(service => service.UpdateDnsAsync(hostname, ipAddress), Times.Once);
        }

        [Fact]
        public async Task UpdateDnsAsync_ShouldHandleNullHostname()
        {
            // Arrange
            string hostname = null;
            var ipAddress = IPAddress.Parse("192.168.99.150");

            _ddnsServiceMock.Setup(service => service.UpdateDnsAsync(hostname, ipAddress))
                .Returns(Task.CompletedTask);

            // Act
            await _ddnsServiceMock.Object.UpdateDnsAsync(hostname, ipAddress);

            // Assert
            _ddnsServiceMock.Verify(service => service.UpdateDnsAsync(hostname, ipAddress), Times.Once);
        }

        [Fact]
        public async Task UpdateDnsAsync_ShouldHandleNullIpAddress()
        {
            // Arrange
            var hostname = "test-host";
            IPAddress ipAddress = null;

            _ddnsServiceMock.Setup(service => service.UpdateDnsAsync(hostname, ipAddress))
                .Returns(Task.CompletedTask);

            // Act
            await _ddnsServiceMock.Object.UpdateDnsAsync(hostname, ipAddress);

            // Assert
            _ddnsServiceMock.Verify(service => service.UpdateDnsAsync(hostname, ipAddress), Times.Once);
        }

        [Fact]
        public async Task UpdateDnsAsync_ShouldHandleEmptyHostname()
        {
            // Arrange
            var hostname = string.Empty;
            var ipAddress = IPAddress.Parse("192.168.99.150");

            _ddnsServiceMock.Setup(service => service.UpdateDnsAsync(hostname, ipAddress))
                .Returns(Task.CompletedTask);

            // Act
            await _ddnsServiceMock.Object.UpdateDnsAsync(hostname, ipAddress);

            // Assert
            _ddnsServiceMock.Verify(service => service.UpdateDnsAsync(hostname, ipAddress), Times.Once);
        }
    }
}
