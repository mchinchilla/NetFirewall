using Moq;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;

namespace NetFirewall.Tests.Dhcp
{
    public class DhcpConfigServiceTests
    {
        private readonly Mock<IDhcpConfigService> _dhcpConfigServiceMock;

        public DhcpConfigServiceTests()
        {
            _dhcpConfigServiceMock = new Mock<IDhcpConfigService>();
        }

        [Fact]
        public async Task GetConfigAsync_ShouldReturnDhcpConfig()
        {
            // Arrange
            var expectedConfig = new DhcpConfig
            {
                SubnetMask = IPAddress.Parse( "255.255.255.0" ),
                Gateway = IPAddress.Parse( "192.168.1.1" ),
                DnsServers = new IPAddress[] { IPAddress.Parse( "8.8.8.8" ), IPAddress.Parse( "8.8.4.4" ) },
                LeaseTime = 3600
            };

            _dhcpConfigServiceMock.Setup( service => service.GetConfigAsync() )
                .ReturnsAsync( expectedConfig );

            // Act
            var result = await _dhcpConfigServiceMock.Object.GetConfigAsync();

            // Assert
            Assert.NotNull( result );
            Assert.Equal( expectedConfig.SubnetMask, result.SubnetMask );
            Assert.Equal( expectedConfig.Gateway, result.Gateway );
            Assert.Equal( expectedConfig.DnsServers, result.DnsServers );
            Assert.Equal( expectedConfig.LeaseTime, result.LeaseTime );
        }

        [Fact]
        public async Task GetConfigAsync_ShouldHandleNullConfig()
        {
            // Arrange
            _dhcpConfigServiceMock.Setup( service => service.GetConfigAsync() )!
                .ReturnsAsync( (DhcpConfig)null );

            // Act
            var result = await _dhcpConfigServiceMock.Object.GetConfigAsync();

            // Assert
            Assert.Null( result );
        }

        [Fact]
        public async Task GetConfigAsync_ShouldHandleEmptyDnsServers()
        {
            // Arrange
            var expectedConfig = new DhcpConfig
            {
                SubnetMask = IPAddress.Parse("255.255.255.0"),
                Gateway = IPAddress.Parse("192.168.1.1"),
                DnsServers = new IPAddress[] { },
                LeaseTime = 3600
            };

            _dhcpConfigServiceMock.Setup( service => service.GetConfigAsync() )
                .ReturnsAsync( expectedConfig );

            // Act
            var result = await _dhcpConfigServiceMock.Object.GetConfigAsync();

            // Assert
            Assert.NotNull( result );
            Assert.Empty( result.DnsServers );
        }
    }
}