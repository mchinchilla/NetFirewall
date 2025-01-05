using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;

namespace NetFirewall.DhcpServer;

public class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly IServiceScopeFactory _serviceScopeFactory;
    private readonly IConfiguration _configuration;

    public Worker( ILogger<Worker> logger, IServiceScopeFactory serviceScopeFactory, IConfiguration configuration )
    {
        _logger = logger;
        _serviceScopeFactory = serviceScopeFactory;
        _configuration = configuration;
    }

    protected override async Task ExecuteAsync( CancellationToken stoppingToken )
    {
        _logger.LogInformation( "DHCP Server is running." );
        string? interfaceIpAddress = _configuration.GetSection( "DHCP:Server:Address" ).Value ?? "0.0.0.0";
        var localEndPoint = new IPEndPoint( IPAddress.Parse( interfaceIpAddress ), 67 );

        using ( var udpClient = new UdpClient( localEndPoint ) )
        {
            while ( !stoppingToken.IsCancellationRequested )
            {
                try
                {
                    var receiveResult = await udpClient.ReceiveAsync( stoppingToken );
                    using ( var scope = _serviceScopeFactory.CreateScope() )
                    {
                        var dhcpServerService = scope.ServiceProvider.GetRequiredService<IDhcpServerService>();
                        var request = ParseDhcpRequest( receiveResult.Buffer, receiveResult.RemoteEndPoint );
                        // Log the request for debugging purposes
                        
                        if ( request != null )
                        {
                            _logger.LogInformation( $"ExecuteAsync:: Mac: {request.ClientMac}, Ip: {request.RequestedIp}, ClientIp: {request.ClientIp}, {request.Hostname}, {request.MessageType}, {request.RemoteEndPoint}" );
                            
                            var response = await dhcpServerService.CreateDhcpResponse( request );
                            
                            IPEndPoint ipEndPoint = new IPEndPoint(IPAddress.Broadcast, 68);
                            _logger.LogInformation( $"Sending response to mac address: {request.ClientMac}, IpEndpoint: {ipEndPoint.Address}:{ipEndPoint.Port} Family: {ipEndPoint.AddressFamily}" );
                            await udpClient.SendAsync( response, response.Length, ipEndPoint );
                        }
                    }
                }
                catch ( OperationCanceledException )
                {
                    // Handle graceful shutdown
                    _logger.LogInformation( "DHCP Server is shutting down." );
                    break;
                }
                catch ( Exception ex )
                {
                    _logger.LogError( $"Error processing DHCP request: {ex.Message}" );
                }
            }
        }
    }

    private DhcpRequest? ParseDhcpRequest( byte[] buffer, IPEndPoint remoteEndPoint )
    {
        try
        {
            // Assuming buffer starts with the standard DHCP packet structure:
            // - 236 bytes of fixed fields (including op, htype, hlen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file)
            // - followed by optional parameters (options)

            // Check if we have enough data for the fixed part of the DHCP packet
            if ( buffer.Length < 236 )
            {
                _logger.LogWarning( "Received DHCP packet is too short to contain valid data." );
                return null;
            }

            DhcpRequest request = new DhcpRequest();
            
            // Extract Client MAC address (chaddr field, 16 bytes, but only first 6 are MAC for Ethernet)
            request.ClientMac = BitConverter.ToString( buffer, 28, 6 ).Replace( "-", ":" );
            
            // Extract Transaction ID (xid, 4 bytes, starting at byte 4)
            request.Xid = new byte[4];
            Array.Copy(buffer, 4, request.Xid, 0, 4);
            
            // Check if the request is relayed (giaddr != 0.0.0.0)
            var giaddrBytes = new byte[4];
            Array.Copy(buffer, 24, giaddrBytes, 0, 4);
            var giaddr = new IPAddress(giaddrBytes);
        
            if (giaddr != IPAddress.Any)
            {
                // If relayed, use giaddr for the remote endpoint
                request.RemoteEndPoint = new IPEndPoint(giaddr, remoteEndPoint.Port);
            }
            else
            {
                request.RemoteEndPoint = remoteEndPoint;
            }
            _logger.LogInformation($"Received from {remoteEndPoint}; giaddr: {giaddr}");

            // Determine if it's a BOOTP request (checking the op field)
            request.IsBootp = buffer[0] == 1; // op code 1 for BOOTP/DHCP request

            // Parse DHCP options which start after the fixed part of the packet
            for ( int i = 240; i < buffer.Length; i++ )
            {
                byte optionCode = buffer[i];
                if ( optionCode == (byte)DhcpOptionCode.End )
                {
                    break; // End of options list
                }
                else if ( optionCode == (byte)DhcpOptionCode.Pad )
                {
                    continue; // Ignore padding
                }

                // Option length is the next byte after the code
                int optionLength = buffer[++i];
                if ( i + optionLength >= buffer.Length )
                {
                    _logger.LogWarning( "DHCP packet option data overflow." );
                    break;
                }

                byte[] optionData = new byte[ optionLength ];
                Array.Copy( buffer, i + 1, optionData, 0, optionLength );

                // Parse specific options
                switch ( (DhcpOptionCode)optionCode )
                {
                    case DhcpOptionCode.MessageType:
                        request.MessageType = (DhcpMessageType)optionData[0];
                        break;
                    case DhcpOptionCode.RequestedIPAddress:
                        request.RequestedIp = new IPAddress( optionData );
                        break;
                    case DhcpOptionCode.ClientIdentifier:
                        // Here you might further parse the client identifier if needed
                        break;
                    case DhcpOptionCode.HostName:
                        request.Hostname = System.Text.Encoding.ASCII.GetString( optionData );
                        break;
                    // Add more cases for other options you want to handle
                }

                i += optionLength; // Move past the data we just processed
            }

            // PXE detection might be based on vendor class identifier or other PXE-specific options
            request.IsPxeRequest = CheckForPxeRequest( buffer );

            _logger.LogInformation( $"Request Info => Mac: {request.ClientMac}, Ip: {request.RequestedIp}, MsgType: {request.MessageType}, IsPxe: {request.IsPxeRequest}, isBootp: {request.IsBootp}, leaseTime; {request.LeaseTime} sec" );
            return request;
        }
        catch ( Exception ex )
        {
            _logger.LogError( $"Error parsing DHCP request: {ex.Message}" );
            return null;
        }
    }


    private bool CheckForPxeRequest( byte[] buffer )
    {
        for ( int i = 240; i < buffer.Length; i++ )
        {
            byte optionCode = buffer[i];
            if ( optionCode == (byte)DhcpOptionCode.End )
            {
                return false;
            }
            else if ( optionCode == (byte)DhcpOptionCode.Pad )
            {
                continue;
            }

            int optionLength = buffer[++i];
            if ( i + optionLength >= buffer.Length )
            {
                return false;
            }

            if ( optionCode == (byte)DhcpOptionCode.VendorClassIdentifier )
            {
                string vendorClass = System.Text.Encoding.ASCII.GetString( buffer, i + 1, optionLength );
                // PXE clients might send "PXEClient" in the Vendor Class Identifier
                if ( vendorClass.Contains( "PXEClient" ) )
                {
                    return true;
                }
            }

            i += optionLength; // Move past the data we just processed
        }

        return false;
    }
}