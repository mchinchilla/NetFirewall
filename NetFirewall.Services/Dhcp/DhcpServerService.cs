using NetFirewall.Models.Dhcp;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using NetFirewall.Services.Dhcp;
using Microsoft.Extensions.Logging;

namespace NetFirewall.Services.Dhcp;

public class DhcpServerService : IDhcpServerService
{
    private readonly IDhcpConfigService _dhcpConfigService;
    private readonly IDhcpLeasesService _leasesService;
    private readonly IDdnsService _ddnsService;
    private readonly ILogger _logger;

    public DhcpServerService( IDhcpConfigService dhcpConfigService, IDhcpLeasesService leasesService, IDdnsService ddnsService, ILogger<DhcpServerService> logger )
    {
        _dhcpConfigService = dhcpConfigService;
        _leasesService = leasesService;
        _ddnsService = ddnsService;
        _logger = logger;
    }

    public async Task<byte[]> CreateDhcpResponse( DhcpRequest request )
    {
        try
        {
            var config = await _dhcpConfigService.GetConfigAsync();
            var options = new List<DhcpOption>();

            options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.SubnetMask, config.SubnetMask.GetAddressBytes() ) );
            options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.Router, config.Gateway.GetAddressBytes() ) );
            options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.DNS, config.DnsServers.SelectMany( ip => ip.GetAddressBytes() ).ToArray() ) );

            if ( request.IsBootp )
            {
                options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.BootFileName, config.BootFileName ?? string.Empty ) );
                options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.ServerName, config.ServerName ?? string.Empty ) );
            }

            if ( request.IsPxeRequest )
            {
                options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.PxeClientArchType, new byte[] { 0x00, 0x07 } ) ); // x86_64
                options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.PxeClientNetworkInterface, new byte[] { 0x01 } ) ); // Ethernet
                options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.PxeDiscoveryControl, new byte[] { 0x03 } ) ); // PXE boot server discovery
            }

            var assignedIp = await _leasesService.AssignOrGetLeaseAsync( request.ClientMac, config.IpRangeStart, config.IpRangeEnd, request );
            options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.YiAddr, assignedIp.GetAddressBytes() ) );

            return ConstructDhcpPacket( request, assignedIp, options );
        }
        catch ( Exception ex )
        {
            _logger.LogError( $"Failed to create DHCP response: {ex.Message}" );
            return new byte[ 0 ]; // Return an empty response or handle based on your protocol
        }
    }

    private byte[] ConstructDhcpPacket( DhcpRequest request, IPAddress assignedIp, List<DhcpOption> options )
    {
        // Placeholder for constructing actual DHCP packet
        return new byte[ 0 ];
    }
}