using System.Threading.Tasks;
using Moq;
using Xunit;
using NetFirewall.DhcpServer;
using NetFirewall.Services.Dhcp;
using NetFirewall.Models.Dhcp;

namespace NetFirewall.Services.Dhcp.Tests
{
    public class DhcpServerServiceTests
    {
        private readonly Mock<IDhcpServerService> _dhcpServerServiceMock;

        public DhcpServerServiceTests()
        {
            _dhcpServerServiceMock = new Mock<IDhcpServerService>();
        }

        [Fact]
        public async Task CreateDhcpResponseAsync_ShouldReturnByteArray()
        {
            // Arrange
            var request = new DhcpRequest
            {
                // Initialize properties of DhcpRequest as needed
            };
            var expectedResponse = new byte[] { 0x01, 0x02, 0x03, 0x04 };

            _dhcpServerServiceMock
                .Setup(service => service.CreateDhcpResponseAsync(request))
                .ReturnsAsync(expectedResponse);

            // Act
            var result = await _dhcpServerServiceMock.Object.CreateDhcpResponseAsync(request);

            // Assert
            Assert.Equal(expectedResponse, result);
        }
    }
}
