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
        string? interfaceIpAddress = _configuration.GetSection( "DHCP:Server:Address" ).Value ?? "127.0.0.1";
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
                        var request = ParseDhcpRequest( receiveResult.Buffer );

                        if ( request != null )
                        {
                            var response = await dhcpServerService.CreateDhcpResponse( request );
                            await udpClient.SendAsync( response, response.Length, receiveResult.RemoteEndPoint );
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

    private DhcpRequest? ParseDhcpRequest( byte[] buffer )
    {
        try
        {
            // Placeholder for parsing DHCP request
            return new DhcpRequest { ClientMac = "00:00:00:00:00:00", IsBootp = false, IsPxeRequest = false };
        }
        catch ( Exception ex )
        {
            _logger.LogError( $"Error parsing DHCP request: {ex.Message}" );
            return null;
        }
    }
}