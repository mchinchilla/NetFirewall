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
            udpClient.EnableBroadcast = true;
            udpClient.Client.SetSocketOption( SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true );

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
                            _logger.LogInformation( $"ExecuteAsync:: Mac: {request.ClientMac}, Ip: {request.RequestedIp}, {request.Hostname}, {request.MessageType}, {request.RemoteEndPoint}" );

                            var response = await dhcpServerService.CreateDhcpResponse( request );

                            if (response.Length > 0)
                            {
                                IPEndPoint targetEndPoint = request.RemoteEndPoint;

                                // Check if the IP address is 0.0.0.0 and replace it with a broadcast address
                                if (targetEndPoint.Address.Equals(IPAddress.Any))
                                {
                                    targetEndPoint = new IPEndPoint(IPAddress.Broadcast, targetEndPoint.Port);
                                }

                                // Log the response size or some details for monitoring
                                _logger.LogInformation( $"Sending {response.Length} bytes to {request.RemoteEndPoint}" );
                                _logger.LogInformation( $"Sending response to mac address: {request.ClientMac}, IpEndpoint: {request.RemoteEndPoint.Address}:{request.RemoteEndPoint.Port} Family: {request.RemoteEndPoint.AddressFamily}" );
                                await udpClient.SendAsync( response, response.Length, request.RemoteEndPoint );
                                _logger.LogInformation( "Data sent successfully." );
                            }
                            else
                            {
                                _logger.LogWarning( "No response was generated for the DHCP request." );
                            }
                        }
                    }
                }
                catch ( SocketException ex )
                {
                    _logger.LogError( $"SocketException: {ex.Message} (ErrorCode: {ex.ErrorCode})" );
                    if ( ex.SocketErrorCode == SocketError.ConnectionReset )
                    {
                        _logger.LogError( "The connection was forcibly closed by the remote host." );
                    }
                    else
                    {
                        _logger.LogError( $"Unexpected socket error: {ex.SocketErrorCode}" );
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
            if ( buffer.Length < 236 )
            {
                _logger.LogWarning( "Received DHCP packet is too short to contain valid data." );
                return null;
            }

            var request = new DhcpRequest
            {
                Op = buffer[0],
                HType = buffer[1],
                HLen = buffer[2],
                Hops = buffer[3],
                Xid = new byte[ 4 ],
                Secs = BitConverter.ToUInt16( buffer, 8 ),
                Flags = BitConverter.ToUInt16( buffer, 10 ),
                CiAddr = new IPAddress( buffer.Skip( 12 ).Take( 4 ).ToArray() ),
                YiAddr = new IPAddress( buffer.Skip( 16 ).Take( 4 ).ToArray() ),
                SiAddr = new IPAddress( buffer.Skip( 20 ).Take( 4 ).ToArray() ),
                GiAddr = new IPAddress( buffer.Skip( 24 ).Take( 4 ).ToArray() ),
                ClientMac = BitConverter.ToString( buffer, 28, 6 ).Replace( "-", ":" )
            };

            Array.Copy( buffer, 4, request.Xid, 0, 4 );

            // Parse MAC address
            byte[] chaddr = new byte[ 16 ];
            Array.Copy( buffer, 28, chaddr, 0, 16 );
            request.ChAddr = chaddr;

            // Parse Server Host Name and Boot File name (both 64 bytes in the packet, but we'll only take the useful part)
            request.SName = System.Text.Encoding.ASCII.GetString( buffer, 44, 64 ).TrimEnd( '\0' );
            request.File = System.Text.Encoding.ASCII.GetString( buffer, 108, 128 ).TrimEnd( '\0' );

            // Magic Cookie - should be 99.130.83.99 (63.82.53.63 in hex)
            if ( buffer[236] != 99 || buffer[237] != 130 || buffer[238] != 83 || buffer[239] != 99 )
            {
                _logger.LogWarning( "Invalid DHCP magic cookie." );
                return null;
            }

            // Parse Options
            ParseOptions( buffer, 240, request );

            // Determine if it's a BOOTP request
            request.IsBootp = request.Op == 1;

            // Check for PXE request - this might require additional logic based on options or other criteria
            request.IsPxeRequest = CheckForPxeRequest( buffer );

            request.RemoteEndPoint = remoteEndPoint;

            return request;
        }
        catch ( Exception ex )
        {
            _logger.LogError( $"Error parsing DHCP request: {ex.Message}" );
            return null;
        }
    }

    private void ParseOptions( byte[] buffer, int startOffset, DhcpRequest request )
    {
        for ( int i = startOffset; i < buffer.Length; i++ )
        {
            byte optionCode = buffer[i];
            if ( optionCode == (byte)DhcpOptionCode.End )
            {
                break;
            }
            else if ( optionCode == (byte)DhcpOptionCode.Pad )
            {
                continue;
            }

            int optionLength = buffer[++i];
            if ( i + optionLength >= buffer.Length )
            {
                _logger.LogWarning( "DHCP packet option data overflow." );
                break;
            }

            byte[] optionData = new byte[ optionLength ];
            Array.Copy( buffer, i + 1, optionData, 0, optionLength );

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
                    request.ClientIdentifier = optionData;
                    break;
                case DhcpOptionCode.HostName:
                    request.Hostname = System.Text.Encoding.ASCII.GetString( optionData );
                    break;
                case DhcpOptionCode.ParameterRequestList:
                    request.ParameterRequestList = optionData;
                    break;
                case DhcpOptionCode.VendorClassIdentifier:
                    request.VendorClassIdentifier = System.Text.Encoding.ASCII.GetString( optionData );
                    break;
                case DhcpOptionCode.IPAddressLeaseTime:
                    request.LeaseTime = BitConverter.ToInt32( optionData, 0 );
                    break;
                // Add more cases for other options you want to handle
            }

            i += optionLength; // Move past the data we just processed
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