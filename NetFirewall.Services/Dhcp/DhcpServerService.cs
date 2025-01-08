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
using Serilog;
using ILogger = Microsoft.Extensions.Logging.ILogger;

namespace NetFirewall.Services.Dhcp;

public class DhcpServerService : IDhcpServerService
{
    private readonly IDhcpConfigService _dhcpConfigService;
    private readonly IDhcpLeasesService _dhcpLeasesService;
    private readonly ILogger _logger;
    private DhcpConfig _dhcpConfig;

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
            _logger.LogDebug( $"CreateDhcpResponse :: Creating DHCP response for {request.ClientMac}" );
            var config = await _dhcpConfigService.GetConfigAsync();
            _logger.LogDebug( $"CreateDhcpResponse :: GetConfigAsync: {config}" );

            _dhcpConfig = config;

            _logger.LogDebug( $"CreateDhcpResponse :: Before List<DhcpOption> options" );

            var now = DateTime.UtcNow;
            List<DhcpOption> options =
            [
                DhcpOptionExtensions.CreateOption( DhcpOptionCode.ServerIdentifier, _dhcpConfig.ServerIp.GetAddressBytes() ),
                DhcpOptionExtensions.CreateOption( DhcpOptionCode.SubnetMask, _dhcpConfig.SubnetMask.GetAddressBytes() ),
                DhcpOptionExtensions.CreateOption( DhcpOptionCode.Router, _dhcpConfig.Gateway.GetAddressBytes() ),
                DhcpOptionExtensions.CreateOption( DhcpOptionCode.DNS, _dhcpConfig.DnsServers.SelectMany( ip => ip.GetAddressBytes() ).ToArray() )
            ];

            _logger.LogDebug( $"CreateDhcpResponse :: After List<DhcpOption> options" );

            _logger.LogDebug( $"CreateDhcpResponse :: Before if ( request.IsBootp )" );
            if ( request.IsBootp )
            {
                options.AddRange( HandleBootpOptions( _dhcpConfig ) );
            }

            _logger.LogDebug( $"CreateDhcpResponse :: After if ( request.IsBootp )" );

            _logger.LogDebug( $"CreateDhcpResponse :: Before if ( request.IsPxeRequest )" );
            if ( request.IsPxeRequest )
            {
                options.AddRange( GetPxeOptions() );
            }

            _logger.LogDebug( $"CreateDhcpResponse :: After if ( request.IsPxeRequest )" );

            _logger.LogDebug( $"CreateDhcpResponse :: Before switch ( request.MessageType )" );

            // Handle DHCP message types
            switch ( request.MessageType )
            {
                case DhcpMessageType.Discover:
                    _logger.LogDebug( $"CreateDhcpResponse :: DHCP DISCOVER from {request.ClientMac}" );
                    return await HandleDiscover( request, options );
                case DhcpMessageType.Request:
                    _logger.LogDebug( $"CreateDhcpResponse :: DHCP REQUEST from {request.ClientMac}" );
                    return await HandleRequest( request, options );
                case DhcpMessageType.Release:
                    _logger.LogDebug( $"CreateDhcpResponse :: DHCP RELEASE from {request.ClientMac}" );
                    await HandleRelease( request );
                    _logger.LogDebug( $"CreateDhcpResponse :: DHCP RELEASE from {request.ClientMac} handled" );
                    return new byte[ 0 ]; // No response for RELEASE
                case DhcpMessageType.Decline:
                    _logger.LogDebug( $"CreateDhcpResponse :: DHCP DECLINE from {request.ClientMac}" );
                    await HandleDecline( request );
                    return new byte[ 0 ]; // No response for DECLINE
                case DhcpMessageType.Inform:
                    _logger.LogDebug( $"CreateDhcpResponse :: DHCP INFORM from {request.ClientMac}" );
                    return HandleInform( request, options );
                default:
                    _logger.LogWarning( $"CreateDhcpResponse :: Unhandled DHCP message type: {request.MessageType}" );
                    return ConstructDhcpPacket( request, IPAddress.Any, new List<DhcpOption> { DhcpOptionExtensions.CreateOption( DhcpOptionCode.MessageType, new byte[] { (byte)DhcpMessageType.Nak } ) } );
            }

            _logger.LogDebug( $"After switch ( request.MessageType )" );
        }
        catch ( Exception ex )
        {
            _logger.LogError( $"CreateDhcpResponse :: Failed to create DHCP response: {ex.Message}" );
            return [ ]; // Return an empty response or handle based on your protocol
        }
    }

    private List<DhcpOption> HandleBootpOptions( DhcpConfig config )
    {
        _logger.LogDebug( "Handling BOOTP options" );
        return new List<DhcpOption>
        {
            DhcpOptionExtensions.CreateOption( DhcpOptionCode.BootFileName, config.BootFileName ?? string.Empty ),
            DhcpOptionExtensions.CreateOption( DhcpOptionCode.TFTPServerName, config.ServerName ?? string.Empty )
        };
    }

    private List<DhcpOption> GetPxeOptions()
    {
        _logger.LogDebug( "Getting PXE options" );
        return new List<DhcpOption>
        {
            DhcpOptionExtensions.CreateOption( DhcpOptionCode.PxeClientArchType, [ 0x00, 0x07 ] ), // x86_64 as an example
            DhcpOptionExtensions.CreateOption( DhcpOptionCode.PxeClientNetworkInterface, [ 0x01 ] ), // Ethernet
            DhcpOptionExtensions.CreateOption( DhcpOptionCode.PxeDiscoveryControl, [ 0x03 ] ) // PXE boot server discovery
        };
    }

    private async Task<byte[]> HandleDiscover( DhcpRequest request, List<DhcpOption> baseOptions )
    {
        _logger.LogDebug( $"Handling DHCP DISCOVER from {request.ClientMac}" );

        _logger.LogDebug( $"HandleDiscover :: Before _dhcpLeasesService.OfferLease" );
        IPAddress? offeredIp = await _dhcpLeasesService.OfferLease( request.ClientMac, _dhcpConfig.IpRangeStart, _dhcpConfig.IpRangeEnd );
        _logger.LogDebug( $"HandleDiscover :: After _dhcpLeasesService.OfferLease" );

        _logger.LogDebug( $"Before if ( offeredIp == null )" );
        if ( offeredIp == null )
        {
            _logger.LogWarning( $"HandleDiscover :: No available IP for client {request.ClientMac}" );
            return ConstructDhcpPacket( request, IPAddress.Any, new List<DhcpOption> { DhcpOptionExtensions.CreateOption( DhcpOptionCode.MessageType, [ (byte)DhcpMessageType.Nak ] ) } );
        }

        _logger.LogDebug( $"HandleDiscover :: After if ( offeredIp == null )" );

        _logger.LogDebug( $"HandleDiscover :: Before List<DhcpOption>" );
        var options = new List<DhcpOption>( baseOptions )
        {
            DhcpOptionExtensions.CreateOption( DhcpOptionCode.MessageType, [ (byte)DhcpMessageType.Offer ] ),
            DhcpOptionExtensions.CreateOption( DhcpOptionCode.RequestedIPAddress, offeredIp.GetAddressBytes() ),
            DhcpOptionExtensions.CreateOption( DhcpOptionCode.IPAddressLeaseTime, BitConverter.GetBytes( IPAddress.HostToNetworkOrder( _dhcpConfig.LeaseTime ) ) )
        };
        _logger.LogDebug( $"HandleDiscover :: After List<DhcpOption>" );

        return ConstructDhcpPacket( request, offeredIp, options );
    }

    private async Task<byte[]> HandleRequest( DhcpRequest request, List<DhcpOption> baseOptions )
    {
        _logger.LogDebug( $"Handling DHCP REQUEST from {request.ClientMac}" );

        IPAddress requestedIp = request.RequestedIp;
        _logger.LogDebug( $"Requested IP: {requestedIp}" );

        if ( await _dhcpLeasesService.CanAssignIp( request.ClientMac, requestedIp ) )
        {
            _logger.LogDebug( $"Request for IP {requestedIp} accepted for client {request.ClientMac}" );
            await _dhcpLeasesService.AssignLease( request.ClientMac, requestedIp, _dhcpConfig.LeaseTime );
            _logger.LogDebug( $"Lease assigned for IP {requestedIp} to client {request.ClientMac}" );

            var options = new List<DhcpOption>( baseOptions )
            {
                DhcpOptionExtensions.CreateOption( DhcpOptionCode.MessageType, new byte[] { (byte)DhcpMessageType.Ack } ),
                DhcpOptionExtensions.CreateOption( DhcpOptionCode.RequestedIPAddress, requestedIp.GetAddressBytes() ),
                DhcpOptionExtensions.CreateOption( DhcpOptionCode.ServerIdentifier, BitConverter.GetBytes( IPAddress.HostToNetworkOrder( _dhcpConfig.ServerIp.GetHashCode() ) ) ),
                DhcpOptionExtensions.CreateOption( DhcpOptionCode.IPAddressLeaseTime, BitConverter.GetBytes( IPAddress.HostToNetworkOrder( _dhcpConfig.LeaseTime ) ) )
            };

            return ConstructDhcpPacket( request, requestedIp, options );
        }
        else
        {
            _logger.LogWarning( $"Request for IP {requestedIp} denied for client {request.ClientMac}" );
            return ConstructDhcpPacket( request, IPAddress.Any, new List<DhcpOption> { DhcpOptionExtensions.CreateOption( DhcpOptionCode.MessageType, new byte[] { (byte)DhcpMessageType.Nak } ) } );
        }
    }

    private async Task<byte[]> HandleRelease( DhcpRequest request )
    {
        _logger.LogDebug( $"Handling DHCP RELEASE from {request.ClientMac}" );
        _logger.LogDebug( $"HandleRelease :: Before _dhcpLeasesService.ReleaseLease" );
        await _dhcpLeasesService.ReleaseLease( request.ClientMac );
        _logger.LogDebug( $"HandleRelease :: After _dhcpLeasesService.ReleaseLease" );

        return [ ]; // No response packet for RELEASE in RFC 2131
    }

    private async Task<byte[]> HandleDecline( DhcpRequest request )
    {
        _logger.LogDebug( $"Handling DHCP DECLINE from {request.ClientMac}" );
        _logger.LogDebug( $"HandleDecline :: Before _dhcpLeasesService.MarkIpAsDeclined" );
        await _dhcpLeasesService.MarkIpAsDeclined( request.RequestedIp );
        _logger.LogDebug( $"HandleDecline :: After _dhcpLeasesService.MarkIpAsDeclined" );

        return [ ]; // No response packet for DECLINE in RFC 2131
    }

    private byte[] HandleInform( DhcpRequest request, List<DhcpOption> baseOptions )
    {
        _logger.LogDebug( $"Handling DHCP INFORM from {request.ClientMac}" );

        _logger.LogDebug( $"HandleInform :: Before List<DhcpOption>" );
        var options = new List<DhcpOption>( baseOptions )
        {
            DhcpOptionExtensions.CreateOption( DhcpOptionCode.MessageType, [ (byte)DhcpMessageType.Ack ] )
        };
        _logger.LogDebug( $"HandleInform :: After List<DhcpOption>" );

        return ConstructDhcpPacket( request, request.RequestedIp, options );
    }

    private byte[] ConstructDhcpPacket( DhcpRequest request, IPAddress assignedIp, List<DhcpOption> options )
    {
        _logger.LogDebug( $"Constructing DHCP packet for {request.ClientMac}" );
        try
        {
            // Define DHCP packet fields
            byte op = 2; // 2 for server reply, 1 for client request
            byte htype = 1; // Ethernet (10Mb)
            byte hlen = 6; // Hardware address length for Ethernet
            byte hops = 0;
            uint xid = BitConverter.ToUInt32( request.Xid, 0 ); // Transaction ID from the request
            ushort secs = 0; // Seconds elapsed since client began address acquisition or renewal process
            ushort flags = 0; // Flags (broadcast flag if set to 0x8000)
            IPAddress ciaddr = request.RequestedIp ?? IPAddress.Any; // Client IP address
            IPAddress yiaddr = assignedIp ?? IPAddress.Any; // 'Your' (client) IP address
            IPAddress siaddr = _dhcpConfig.ServerIp; // Server IP address
            IPAddress giaddr = IPAddress.Any; // Relay agent IP address

            // Hardware address padding (16 bytes for chaddr, but only first 6 are used for MAC)
            byte[] chaddr = new byte[ 16 ];
            Array.Copy( MacStringToBytes( request.ClientMac ), 0, chaddr, 0, 6 );

            // Server name and boot file name, both 64 bytes
            byte[] sname = new byte[ 64 ];
            byte[] file = new byte[ 128 ];
            if ( request.IsBootp )
            {
                Encoding.ASCII.GetBytes( _dhcpConfig.ServerName ?? string.Empty ).CopyTo( sname, 0 );
                Encoding.ASCII.GetBytes( _dhcpConfig.BootFileName ?? string.Empty ).CopyTo( file, 0 );
            }

            // Construct the options field
            var optionsBytes = ConstructDhcpOptions( options );

            // Combine all parts into the packet
            using ( var ms = new System.IO.MemoryStream() )
            {
                using ( var bw = new System.IO.BinaryWriter( ms ) )
                {
                    bw.Write( op );
                    bw.Write( htype );
                    bw.Write( hlen );
                    bw.Write( hops );
                    bw.Write( xid );
                    bw.Write( secs );
                    bw.Write( flags );
                    bw.Write( ciaddr.GetAddressBytes() );
                    bw.Write( yiaddr.GetAddressBytes() );
                    bw.Write( siaddr.GetAddressBytes() );
                    bw.Write( giaddr.GetAddressBytes() );
                    bw.Write( chaddr );
                    bw.Write( sname );
                    bw.Write( file );
                    // Magic cookie - must be 99.130.83.99
                    bw.Write( new byte[] { 99, 130, 83, 99 } );
                    bw.Write( optionsBytes );
                    bw.Write( (byte)DhcpOptionCode.End ); // End of options
                }

                return ms.ToArray();
            }
        }
        catch ( Exception ex )
        {
            _logger.LogError( $"Error constructing DHCP packet: {ex.Message}" );
            return [ ];
        }
        finally
        {
            _logger.LogDebug( $"Constructed DHCP packet for {request.ClientMac}" );
        }
    }

    private byte[] ConstructDhcpOptions( List<DhcpOption> options )
    {
        using ( var ms = new System.IO.MemoryStream() )
        {
            using ( var bw = new System.IO.BinaryWriter( ms ) )
            {
                foreach ( var option in options )
                {
                    bw.Write( option.Code );
                    bw.Write( (byte)option.Data.Length ); // length of the option
                    bw.Write( option.Data );
                }
            }

            return ms.ToArray();
        }
    }

    private byte[] MacStringToBytes( string macAddress )
    {
        return macAddress.Split( ':' ).Select( b => Convert.ToByte( b, 16 ) ).ToArray();
    }
}