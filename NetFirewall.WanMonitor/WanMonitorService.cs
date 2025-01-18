using System.Diagnostics;
using System.Net.NetworkInformation;

namespace NetFirewall.WanMonitor;

public class WanMonitorService : BackgroundService
{
    private readonly ILogger<WanMonitorService> _logger;
    private readonly IConfiguration _configuration;
    private string? _currentInterface;
    private string? _currentGateway;
    private string[]? _currentIPs;

    public WanMonitorService( ILogger<WanMonitorService> logger, IConfiguration configuration )
    {
        _logger = logger;
        _configuration = configuration;
        _currentInterface = _configuration[ "Network:PrimaryInterface" ];
        _currentGateway = _configuration[ "Network:PrimaryGateway" ];
        _currentIPs = _configuration.GetSection( "Network:PrimaryIPs" ).Get<string[]>();
    }

    protected override async Task ExecuteAsync( CancellationToken stoppingToken )
    {
        while ( !stoppingToken.IsCancellationRequested )
        {
            try
            {
                await CheckConnectivityAsync( stoppingToken );
            }
            catch ( Exception ex )
            {
                _logger.LogError( ex, "Error during network check." );
            }

            await Task.Delay( TimeSpan.FromSeconds( 30 ), stoppingToken ); // Wait for 30 seconds
        }
    }

    private async Task CheckConnectivityAsync( CancellationToken stoppingToken )
    {
        if ( _currentIPs != null )
        {
            var pingTasks = _currentIPs.Select( ip => PingAsync( ip, stoppingToken ) ).ToArray();
            var results = await Task.WhenAll( pingTasks );

            if ( _currentInterface == _configuration[ "Network:PrimaryInterface" ] && !results.Any( r => r ) )
            {
                _logger.LogInformation( "Switching to secondary gateway." );
                _currentInterface = _configuration[ "Network:SecondaryInterface" ];
                _currentGateway = _configuration[ "Network:SecondaryGateway" ];
                _currentIPs = _configuration.GetSection( "Network:SecondaryIPs" ).Get<string[]>();
                await SwitchGatewayAsync( _currentInterface );
            }
            else if ( _currentInterface == _configuration[ "Network:SecondaryInterface" ] && results.Any( r => r ) )
            {
                _logger.LogInformation( "Switching back to primary gateway." );
                _currentInterface = _configuration[ "Network:PrimaryInterface" ];
                _currentGateway = _configuration[ "Network:PrimaryGateway" ];
                _currentIPs = _configuration.GetSection( "Network:PrimaryIPs" ).Get<string[]>();
                await SwitchGatewayAsync( _currentInterface );
            }
        }
        else
        {
            _logger.LogWarning( "No IPs to check. Skipping connectivity check." );
        }
    }

    private async Task<bool> PingAsync( string ip, CancellationToken token )
    {
        using var ping = new Ping();
        try
        {
            // var reply = await ping.SendPingAsync(IPAddress.Parse(ip), 3000, new byte[32], token);
            var reply = await ping.SendPingAsync( ip, timeout: 3000, new byte[ 32 ] );
            return reply.Status == IPStatus.Success;
        }
        catch ( OperationCanceledException )
        {
            return false; // Task was cancelled
        }
        catch
        {
            return false; // Any other exception, consider it failed
        }
    }

    private async Task SwitchGatewayAsync( string? interfaceName )
    {
        // Here you would implement logic to change the default route. 
        // This is system-specific and usually involves shell commands or direct interaction with network managers.
        // Example (pseudo-code):
        // await RunCommandAsync($"ip route replace default via {_currentGateway} dev {interfaceName}");
        string command = $"ip route replace default via {_currentGateway} dev {interfaceName}";

        var processStartInfo = new ProcessStartInfo
        {
            FileName = "/bin/bash",
            Arguments = $"-c \"{command}\"",
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        try
        {
            using ( var process = new Process() )
            {
                process.StartInfo = processStartInfo;
                process.Start();

                string stdout = await process.StandardOutput.ReadToEndAsync();
                string stderr = await process.StandardError.ReadToEndAsync();

                await process.WaitForExitAsync();

                if ( process.ExitCode != 0 )
                {
                    _logger.LogError( $"Failed to switch gateway. Error: {stderr}" );
                }
                else
                {
                    _logger.LogInformation( $"Successfully switched to gateway via {interfaceName}. Output: {stdout}" );
                }
            }
        }
        catch ( Exception ex )
        {
            _logger.LogError( ex, "An error occurred while trying to switch the gateway." );
        }
    }
}