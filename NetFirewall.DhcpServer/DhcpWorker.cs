using System.Net;
using System.Net.Sockets;
using System.Text;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using System.Threading.Tasks.Dataflow;

namespace NetFirewall.DhcpServer;

public class DhcpWorker : BackgroundService
{
    private readonly ILogger<DhcpWorker> _logger;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly UdpClient _udpClient;
    private readonly BufferBlock<byte[]> _receiveBuffer;

    public DhcpWorker( ILogger<DhcpWorker> logger, IServiceScopeFactory scopeFactory )
    {
        _logger = logger;
        _scopeFactory = scopeFactory;
        _udpClient = new UdpClient( 67 );
        _receiveBuffer = new BufferBlock<byte[]>();
    }

    protected override async Task ExecuteAsync( CancellationToken stoppingToken )
    {
        _logger.LogInformation( "DHCP Server is running." );

        var receiveTask = ReceivePacketsAsync( stoppingToken );
        var processTask = ProcessPacketsAsync( stoppingToken );

        await Task.WhenAll( receiveTask, processTask );
    }

    private async Task ReceivePacketsAsync( CancellationToken stoppingToken )
    {
        try
        {
            while ( !stoppingToken.IsCancellationRequested )
            {
                try
                {
                    var receiveResult = await _udpClient.ReceiveAsync( stoppingToken );

                    _logger.LogInformation( $"Received DHCP packet from {receiveResult.RemoteEndPoint}, {receiveResult.Buffer.Length} bytes" );

                    // Log packet size for monitoring
                    _logger.LogDebug( $"Packet size: {receiveResult.Buffer.Length} bytes" );

                    // Attempt to parse the DHCP message type for further logging
                    if ( receiveResult.Buffer.Length > 240 ) // Ensuring there's enough data for the message type
                    {
                        var messageType = (DhcpMessageType)receiveResult.Buffer[240];
                        _logger.LogInformation( $"Received DHCP message type: {messageType}" );
                    }
                    else
                    {
                        _logger.LogWarning( "Received packet too short to determine message type." );
                    }

                    await _receiveBuffer.SendAsync( receiveResult.Buffer );
                }
                catch ( OperationCanceledException )
                {
                    _logger.LogInformation( "DHCP packet receiving stopped due to cancellation request." );
                    break;
                }
                catch ( SocketException ex ) when ( ex.SocketErrorCode == SocketError.ConnectionReset )
                {
                    _logger.LogWarning( $"Connection reset during receive operation: {ex.Message}" );
                    // Optionally, you might want to delay before continuing if this error occurs frequently
                    await Task.Delay( 500, stoppingToken ); // Example delay
                }
                catch ( SocketException ex )
                {
                    _logger.LogError( $"Socket error occurred while receiving packet: {ex.Message}, ErrorCode: {ex.SocketErrorCode}" );
                }
                catch ( Exception ex )
                {
                    _logger.LogError( $"Unexpected error in packet receiving: {ex.Message}" );
                }
            }
        }
        catch ( Exception ex )
        {
            _logger.LogCritical( $"Critical error in packet receiving loop: {ex.Message}" );
        }
        finally
        {
            _logger.LogInformation( "Exiting DHCP packet receiving loop." );
        }
    }

    private async Task ProcessPacketsAsync( CancellationToken stoppingToken )
    {
        while ( !stoppingToken.IsCancellationRequested || await _receiveBuffer.OutputAvailableAsync( stoppingToken ) )
        {
            try
            {
                var buffer = await _receiveBuffer.ReceiveAsync( stoppingToken );
                using ( var scope = _scopeFactory.CreateScope() )
                {
                    var dhcpService = scope.ServiceProvider.GetRequiredService<IDhcpServerService>();
                    var request = ParseDhcpRequest( buffer );
                    if ( request != null )
                    {
                        var response = await dhcpService.CreateDhcpResponseAsync( request );
                        if ( response != null && response.Length > 0 )
                        {
                            IPEndPoint remoteEndPoint = request.RemoteEndPoint;
                            if(request.RemoteEndPoint == null)
                            {
                                _logger.LogDebug( "RemoteEndPoint is null" );
                                remoteEndPoint = new IPEndPoint( IPAddress.Broadcast, 68 );
                            }
                            await _udpClient.SendAsync( response, response.Length, remoteEndPoint );
                            _logger.LogInformation( $"Sent DHCP response to {remoteEndPoint}" );
                        }
                    }
                }
            }
            catch ( OperationCanceledException )
            {
                _logger.LogInformation( "DHCP packet processing stopped." );
                break;
            }
            catch ( Exception ex )
            {
                _logger.LogError( $"Error processing DHCP packet: {ex.Message}" );
            }
        }
    }

    private DhcpRequest ParseDhcpRequest(byte[] buffer)
    {
        try
        {
            if (buffer.Length < 236) // Minimum DHCP packet length
            {
                _logger.LogWarning("Received DHCP packet is too short to contain valid data.");
                return null;
            }

            var request = new DhcpRequest
            {
                Op = buffer[0],
                HType = buffer[1],
                HLen = buffer[2],
                Hops = buffer[3],
                Xid = new byte[4],
                Secs = BitConverter.ToUInt16(buffer, 8),
                Flags = BitConverter.ToUInt16(buffer, 10),
                CiAddr = ReadIpAddress(buffer, 12),
                YiAddr = ReadIpAddress(buffer, 16),
                SiAddr = ReadIpAddress(buffer, 20),
                GiAddr = ReadIpAddress(buffer, 24),
                ChAddr = new byte[16]
            };

            Array.Copy(buffer, 4, request.Xid, 0, 4);
            Array.Copy(buffer, 28, request.ChAddr, 0, 16);
            request.ClientMac = BitConverter.ToString(buffer, 28, 6).Replace("-", ":");
            request.SName = ReadPaddedString(buffer, 44, 64);
            request.File = ReadPaddedString(buffer, 108, 128);

            // Check for magic cookie
            if (buffer[236] != 99 || buffer[237] != 130 || buffer[238] != 83 || buffer[239] != 99)
            {
                _logger.LogWarning("Invalid DHCP magic cookie in the packet.");
                return null;
            }

            _logger.LogInformation($"Parsing DHCP packet with XID: {BitConverter.ToString(request.Xid)}");

            // Parse options
            for (int i = 240; i < buffer.Length; i++)
            {
                byte optionCode = buffer[i];
                if (optionCode == (byte)DhcpOptionCode.End)
                {
                    _logger.LogDebug("End of DHCP options reached.");
                    break;
                }
                else if (optionCode == (byte)DhcpOptionCode.Pad)
                {
                    _logger.LogDebug("Encountered DHCP option padding.");
                    continue;
                }

                if (i + 1 >= buffer.Length)
                {
                    _logger.LogWarning("Buffer too short to read option length.");
                    break;
                }

                int optionLength = buffer[++i];
                if (i + 1 + optionLength > buffer.Length)
                {
                    _logger.LogWarning("Buffer too short to read option data.");
                    break;
                }

                byte[] optionData = new byte[optionLength];
                Array.Copy(buffer, i + 1, optionData, 0, optionLength);

                _logger.LogDebug($"Parsing DHCP option {optionCode} with length {optionLength}");

                switch ((DhcpOptionCode)optionCode)
                {
                    case DhcpOptionCode.MessageType:
                        request.MessageType = (DhcpMessageType)optionData[0];
                        _logger.LogInformation($"DHCP Message Type: {request.MessageType}");
                        break;
                    case DhcpOptionCode.RequestedIPAddress:
                        request.RequestedIp = new IPAddress(optionData);
                        _logger.LogInformation($"Requested IP: {request.RequestedIp}");
                        break;
                    case DhcpOptionCode.ClientIdentifier:
                        request.ClientIdentifier = optionData;
                        _logger.LogDebug($"Client Identifier: {BitConverter.ToString(optionData)}");
                        break;
                    case DhcpOptionCode.HostName:
                        request.Hostname = Encoding.ASCII.GetString(optionData);
                        _logger.LogInformation($"Client Hostname: {request.Hostname}");
                        break;
                    case DhcpOptionCode.ParameterRequestList:
                        request.ParameterRequestList = optionData;
                        _logger.LogDebug($"Parameter Request List: {string.Join(", ", optionData)}");
                        break;
                    case DhcpOptionCode.VendorClassIdentifier:
                        request.VendorClassIdentifier = Encoding.ASCII.GetString(optionData);
                        _logger.LogInformation($"Vendor Class Identifier: {request.VendorClassIdentifier}");
                        break;
                    case DhcpOptionCode.IPAddressLeaseTime:
                        request.LeaseTime = BitConverter.ToInt32(optionData, 0);
                        _logger.LogInformation($"Requested Lease Time: {request.LeaseTime} seconds");
                        break;
                    // Add more cases for other options as needed
                }

                i += optionLength; // Move past the data we just processed
            }

            // Determine if it's a BOOTP request
            request.IsBootp = request.Op == 1;
            _logger.LogInformation($"BOOTP request: {request.IsBootp}");

            // Check for PXE request
            request.IsPxeRequest = CheckForPxeRequest(buffer);
            _logger.LogInformation($"PXE request: {request.IsPxeRequest}");

            return request;
        }
        catch (Exception ex)
        {
            _logger.LogError($"Error parsing DHCP request: {ex.Message}");
            return null;
        }
    }

    private IPAddress ReadIpAddress(byte[] buffer, int offset)
    {
        if (buffer.Length < offset + 4)
        {
            _logger.LogWarning($"Buffer too short to read IP address at offset {offset}");
            return IPAddress.Any;
        }
        return new IPAddress(buffer.Skip(offset).Take(4).ToArray());
    }

    private string ReadPaddedString(byte[] buffer, int offset, int length)
    {
        if (buffer.Length < offset + length)
        {
            _logger.LogWarning($"Buffer too short to read string at offset {offset} with length {length}");
            return string.Empty;
        }
        return Encoding.ASCII.GetString(buffer, offset, length).TrimEnd('\0');
    }
    
    private bool CheckForPxeRequest( byte[] buffer )
    {
        for ( int i = 240; i < buffer.Length; i++ )
        {
            byte optionCode = buffer[i];
            if ( optionCode == (byte)DhcpOptionCode.VendorClassIdentifier )
            {
                int optionLength = buffer[++i];
                string vendorClass = Encoding.ASCII.GetString( buffer, i + 1, optionLength );
                if ( vendorClass.Contains( "PXEClient" ) )
                {
                    return true;
                }
            }
            else if ( optionCode == (byte)DhcpOptionCode.End ) break;
        }

        return false;
    }
}