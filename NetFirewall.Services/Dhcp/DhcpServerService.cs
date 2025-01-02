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
    private readonly IDhcpLeasesService _dhcpLeasesService;
    private readonly ILogger _logger;

    public DhcpServerService( IDhcpConfigService dhcpConfigService, IDhcpLeasesService dhcpLeasesService, ILogger<DhcpServerService> logger )
    {
        _dhcpConfigService = dhcpConfigService;
        _dhcpLeasesService = dhcpLeasesService;
        _logger = logger;
    }

    public async Task<byte[]> CreateDhcpResponse( DhcpRequest request )
    {
        try
        {
            var config = await _dhcpConfigService.GetConfigAsync();
            var options = new List<DhcpOption>();

            // Common options for all responses
            options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.SubnetMask, config.SubnetMask.GetAddressBytes() ) );
            options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.Router, config.Gateway.GetAddressBytes() ) );
            options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.DNS, config.DnsServers.SelectMany( ip => ip.GetAddressBytes() ).ToArray() ) );

            if ( request.IsBootp )
            {
                options = HandleBootpOptions( config, options );
            }

            if ( request.IsPxeRequest )
            {
                options.AddRange( GetPxeOptions() );
            }

            // Handle DHCP message types
            switch ( request.MessageType )
            {
                case DhcpMessageType.Discover:
                    return await HandleDiscover( request, config, options );
                case DhcpMessageType.Request:
                    return await HandleRequest( request, config, options );
                case DhcpMessageType.Release:
                    return await HandleRelease( request );
                case DhcpMessageType.Decline:
                    return await HandleDecline( request );
                case DhcpMessageType.Inform:
                    return await HandleInform( request, config, options );
                default:
                    _logger.LogWarning( $"Unhandled DHCP message type: {request.MessageType}" );
                    return new byte[0]; // or some default response
            }
        }
        catch ( Exception ex )
        {
            _logger.LogError( $"Failed to create DHCP response: {ex.Message}" );
            return new byte[0]; // Return an empty response or handle based on your protocol
        }
    }

    private List<DhcpOption> HandleBootpOptions( DhcpConfig config, List<DhcpOption> options )
    {
        options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.BootFileName, config.BootFileName ?? string.Empty ) );
        options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.TFTPServerName, config.ServerName ?? string.Empty ) );
        return options;
    }

    private List<DhcpOption> GetPxeOptions()
    {
        return new List<DhcpOption>
        {
            DhcpOptionExtensions.CreateOption( DhcpOptionCode.PxeClientArchType, new byte[] { 0x00, 0x07 } ), // x86_64 as an example
            DhcpOptionExtensions.CreateOption( DhcpOptionCode.PxeClientNetworkInterface, new byte[] { 0x01 } ), // Ethernet
            DhcpOptionExtensions.CreateOption( DhcpOptionCode.PxeDiscoveryControl, new byte[] { 0x03 } ) // PXE boot server discovery
        };
    }

    private async Task<byte[]> HandleDiscover( DhcpRequest request, DhcpConfig config, List<DhcpOption> options )
    {
        var offeredIp = await _dhcpLeasesService.OfferLease( request.ClientMac, config.IpRangeStart, config.IpRangeEnd );
        options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.RequestedIPAddress, offeredIp.GetAddressBytes() ) );
        options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.MessageType, new byte[] { ( byte )DhcpMessageType.Offer } ) );
        options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.ServerIdentifier, BitConverter.GetBytes( IPAddress.HostToNetworkOrder( config.ServerIp.GetHashCode() ) ) ) );
        return ConstructDhcpPacket( request, offeredIp, options );
    }

    private async Task<byte[]> HandleRequest( DhcpRequest request, DhcpConfig config, List<DhcpOption> options )
    {
        var requestedIp = request.RequestedIp ?? await _dhcpLeasesService.GetAssignedIp( request.ClientMac );
        if ( await _dhcpLeasesService.CanAssignIp( request.ClientMac, requestedIp ) )
        {
            await _dhcpLeasesService.AssignLease( request.ClientMac, requestedIp, config.LeaseTime );
            options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.RequestedIPAddress, requestedIp.GetAddressBytes() ) );
            options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.MessageType, new byte[] { ( byte )DhcpMessageType.Ack } ) );
            options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.ServerIdentifier, BitConverter.GetBytes( IPAddress.HostToNetworkOrder( config.ServerIp.GetHashCode() ) ) ) );
            options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.IPAddressLeaseTime, BitConverter.GetBytes( IPAddress.HostToNetworkOrder( config.LeaseTime ) ) ) );
            return ConstructDhcpPacket( request, requestedIp, options );
        }
        else
        {
            options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.MessageType, new byte[] { ( byte )DhcpMessageType.Nak } ) );
            return ConstructDhcpPacket( request, null, options );
        }
    }

    private async Task<byte[]> HandleRelease( DhcpRequest request )
    {
        await _dhcpLeasesService.ReleaseLease( request.ClientMac );
        return new byte[0]; // No response packet for RELEASE in RFC 2131
    }

    private async Task<byte[]> HandleDecline( DhcpRequest request )
    {
        await _dhcpLeasesService.MarkIpAsDeclined( request.RequestedIp );
        return new byte[0]; // No response packet for DECLINE in RFC 2131
    }

    private async Task<byte[]> HandleInform( DhcpRequest request, DhcpConfig config, List<DhcpOption> options )
    {
        options.Add( DhcpOptionExtensions.CreateOption( DhcpOptionCode.MessageType, new byte[] { ( byte )DhcpMessageType.Ack } ) );
        // Add configuration options without IP allocation
        return ConstructDhcpPacket( request, request.ClientIp, options );
    }

    private byte[] ConstructDhcpPacket( DhcpRequest request, IPAddress assignedIp, List<DhcpOption> options )
    {
        // Implementation to construct the DHCP packet according to RFC 2131
        // This would involve setting up the DHCP packet structure, including headers, options, etc.
        return new byte[0]; // Placeholder
    }
}