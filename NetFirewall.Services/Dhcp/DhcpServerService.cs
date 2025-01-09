using System.Net;
using System.Text;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Dhcp;

namespace NetFirewall.Services.Dhcp;

public class DhcpServerService : IDhcpServerService
{
    private readonly IDhcpLeasesService _dhcpLeasesService;
    private readonly ILogger<DhcpServerService> _logger;
    private readonly DhcpConfig _dhcpConfig;

    public DhcpServerService( IDhcpLeasesService dhcpLeasesService, ILogger<DhcpServerService> logger, IOptions<DhcpConfig> dhcpConfig )
    {
        _dhcpLeasesService = dhcpLeasesService;
        _logger = logger;
        _dhcpConfig = new DhcpConfig
        {
            IpRangeStart = IPAddress.Parse( "192.168.99.100" ),
            IpRangeEnd = IPAddress.Parse( "192.168.99.199" ),
            ServerIp = IPAddress.Parse( "192.168.99.1" ),
            SubnetMask = IPAddress.Parse( "255.255.255.0" ),
            Gateway = IPAddress.Parse( "192.168.99.1" ),
            DnsServers = new List<IPAddress> {
                IPAddress.Parse( "1.1.1.1" ),
                IPAddress.Parse( "8.8.8.8" )
            },
            LeaseTime = 86400
        };
    }

    public async Task<byte[]> CreateDhcpResponseAsync( DhcpRequest request )
    {
        try
        {
            var options = new List<DhcpOption>
            {
                DhcpOptionExtensions.CreateOption( DhcpOptionCode.ServerIdentifier, _dhcpConfig.ServerIp.GetAddressBytes() ),
                DhcpOptionExtensions.CreateOption( DhcpOptionCode.SubnetMask, _dhcpConfig.SubnetMask.GetAddressBytes() ),
                DhcpOptionExtensions.CreateOption( DhcpOptionCode.Router, _dhcpConfig.Gateway.GetAddressBytes() ),
                DhcpOptionExtensions.CreateOption( DhcpOptionCode.DNS, _dhcpConfig.DnsServers.SelectMany( ip => ip.GetAddressBytes() ).ToArray() )
            };

            if ( request.IsBootp )
            {
                options.AddRange( HandleBootpOptions( _dhcpConfig ) );
            }

            if ( request.IsPxeRequest )
            {
                options.AddRange( GetPxeOptions() );
            }

            switch ( request.MessageType )
            {
                case DhcpMessageType.Discover:
                    return await HandleDiscoverAsync( request, options );
                case DhcpMessageType.Request:
                    return await HandleRequestAsync( request, options );
                case DhcpMessageType.Release:
                    await HandleReleaseAsync( request );
                    return Array.Empty<byte>(); // No response for RELEASE
                case DhcpMessageType.Decline:
                    await HandleDeclineAsync( request );
                    return Array.Empty<byte>(); // No response for DECLINE
                case DhcpMessageType.Inform:
                    return HandleInform( request, options );
                default:
                    _logger.LogWarning( $"Unhandled DHCP message type: {request.MessageType}" );
                    return ConstructDhcpPacket( request, IPAddress.Any, new List<DhcpOption> { DhcpOptionExtensions.CreateOption( DhcpOptionCode.MessageType, new byte[] { (byte)DhcpMessageType.Nak } ) } );
            }
        }
        catch ( Exception ex )
        {
            _logger.LogError( $"Failed to create DHCP response: {ex.Message}" );
            return ConstructDhcpPacket( request, IPAddress.Any, new List<DhcpOption> { DhcpOptionExtensions.CreateOption( DhcpOptionCode.MessageType, new byte[] { (byte)DhcpMessageType.Nak } ) } );
        }
    }

    private async Task<byte[]> HandleDiscoverAsync( DhcpRequest request, List<DhcpOption> baseOptions )
    {
        try
        {
            var offeredIp = await _dhcpLeasesService.OfferLeaseAsync( request.ClientMac, _dhcpConfig.IpRangeStart, _dhcpConfig.IpRangeEnd );
            if ( offeredIp == null )
            {
                _logger.LogWarning( $"No available IP for client {request.ClientMac}" );
                return ConstructDhcpPacket( request, IPAddress.Any, new List<DhcpOption> { DhcpOptionExtensions.CreateOption( DhcpOptionCode.MessageType, new byte[] { (byte)DhcpMessageType.Nak } ) } );
            }

            var options = new List<DhcpOption>( baseOptions )
            {
                DhcpOptionExtensions.CreateOption( DhcpOptionCode.MessageType, new byte[] { (byte)DhcpMessageType.Offer } ),
                DhcpOptionExtensions.CreateOption( DhcpOptionCode.IPAddressLeaseTime, BitConverter.GetBytes( IPAddress.HostToNetworkOrder( _dhcpConfig.LeaseTime ) ) )
            };
            
            return ConstructDhcpPacket( request, offeredIp, options );
        }
        catch ( Exception ex )
        {
            _logger.LogError( $"Failed to handle DISCOVER: {ex.Message}" );
            return ConstructDhcpPacket( request, IPAddress.Any, new List<DhcpOption> { DhcpOptionExtensions.CreateOption( DhcpOptionCode.MessageType, new byte[] { (byte)DhcpMessageType.Nak } ) } );
        }
    }

    private async Task<byte[]> HandleRequestAsync( DhcpRequest request, List<DhcpOption> baseOptions )
    {
        try
        {
            var requestedIp = request.RequestedIp ?? await _dhcpLeasesService.GetAssignedIpAsync( request.ClientMac );

            if ( requestedIp != null && await _dhcpLeasesService.CanAssignIpAsync( request.ClientMac, requestedIp ) )
            {
                await _dhcpLeasesService.AssignLeaseAsync( request.ClientMac, requestedIp, _dhcpConfig.LeaseTime );

                var options = new List<DhcpOption>( baseOptions )
                {
                    DhcpOptionExtensions.CreateOption( DhcpOptionCode.MessageType, new byte[] { (byte)DhcpMessageType.Ack } ),
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
        catch ( Exception ex )
        {
            _logger.LogError( $"Failed to handle REQUEST: {ex.Message}" );
            return ConstructDhcpPacket( request, IPAddress.Any, new List<DhcpOption> { DhcpOptionExtensions.CreateOption( DhcpOptionCode.MessageType, new byte[] { (byte)DhcpMessageType.Nak } ) } );
        }
    }

    private async Task HandleReleaseAsync( DhcpRequest request )
    {
        await _dhcpLeasesService.ReleaseLeaseAsync( request.ClientMac );
    }

    private async Task HandleDeclineAsync( DhcpRequest request )
    {
        await _dhcpLeasesService.MarkIpAsDeclinedAsync( request.RequestedIp );
    }

    private byte[] HandleInform( DhcpRequest request, List<DhcpOption> baseOptions )
    {
        var options = new List<DhcpOption>( baseOptions )
        {
            DhcpOptionExtensions.CreateOption( DhcpOptionCode.MessageType, new byte[] { (byte)DhcpMessageType.Ack } )
        };
        return ConstructDhcpPacket( request, request.RequestedIp, options );
    }

    private List<DhcpOption> HandleBootpOptions( DhcpConfig config )
    {
        return new List<DhcpOption>
        {
            DhcpOptionExtensions.CreateOption( DhcpOptionCode.BootFileName, config.BootFileName ?? string.Empty ),
            DhcpOptionExtensions.CreateOption( DhcpOptionCode.TFTPServerName, config.ServerName ?? string.Empty )
        };
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