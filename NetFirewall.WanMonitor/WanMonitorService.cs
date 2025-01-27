using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace NetFirewall.WanMonitor;

public class WanMonitorService : BackgroundService
{
    private readonly ILogger<WanMonitorService> _logger;
    private readonly IConfiguration _configuration;
    private readonly string? _currentInterface;
    private readonly string? _currentGateway;
    private readonly string[]? _currentIPs;
    private readonly string? _primaryInterface;
    private readonly string? _secondaryInterface;
    private readonly string? _primaryGateway;
    private readonly string? _secondaryGateway;
    private readonly string[]? _primaryIPs;
    private readonly string[]? _secondaryIPs;


    public WanMonitorService( ILogger<WanMonitorService> logger, IConfiguration configuration )
    {
        _logger = logger;
        _configuration = configuration;
        
        _currentInterface = _configuration[ "Network:PrimaryInterface" ];
        _currentGateway = _configuration[ "Network:PrimaryGateway" ] ?? "";
        
        _primaryGateway = _configuration[ "Network:PrimaryGateway" ] ?? "";
        
        _currentIPs = _configuration.GetSection( "Network:PrimaryIPs" ).Get<string[]>() ?? [ "8.8.8.8", "1.1.1.1" ];
        _primaryIPs = _configuration.GetSection( "Network:PrimaryIPs" ).Get<string[]>() ?? [ "8.8.8.8", "1.1.1.1" ];
        _secondaryIPs = _configuration.GetSection( "Network:SecondaryIPs" ).Get<string[]>() ?? [ "8.8.8.8", "1.1.1.1" ];
    }

    protected override async Task ExecuteAsync( CancellationToken stoppingToken )
    {
        _logger.LogInformation( "WAN Monitor Worker Service started." );

        // Notify systemd that the service is ready
        if ( System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform( System.Runtime.InteropServices.OSPlatform.Linux ) )
        {
            _logger.LogInformation( "Notifying systemd that the service is ready." );
            // Systemd.Notify.Ready();
        }

        var interfaces = new List<NetworkInterfaceConfig>
        {
            new NetworkInterfaceConfig
            {
                InterfaceName = "ens192", // Primary interface
                MonitorIPs = _primaryIPs
            },
            new NetworkInterfaceConfig
            {
                InterfaceName = "ens224", // Backup interface
                MonitorIPs = _secondaryIPs
            }
        };

        // Bash commands to execute when failover occurs
        string[] failoverCommands =
        {
            "echo 'Switching to backup interface'",
            $"ip route replace default via {_secondaryGateway} dev ens224", // Example: change the ip route
            $"/usr/sbin/nft -f /root/working-nftables.conf" // Example: Enable backup interface
        };

        // Bash commands to execute when primary interface is back online
        string[] primaryCommands =
        {
            "echo 'Switching to primary interface'",
            $"ip route replace default via {_primaryGateway} dev ens192", // Example: change the ip route
            $"/usr/sbin/nft -f /etc/nftables.conf" // Example: Enable primary interface
        };

        while ( !stoppingToken.IsCancellationRequested )
        {
            try
            {
                await MonitorInterfacesAsync( interfaces, failoverCommands, primaryCommands, stoppingToken );

                // Notify systemd watchdog (if enabled)
                if ( System.Runtime.InteropServices.RuntimeInformation.IsOSPlatform( System.Runtime.InteropServices.OSPlatform.Linux ) )
                {
                    // Systemd.Notify.Watchdog();
                    _logger.LogInformation( "Notified systemd watchdog." );
                }
            }
            catch ( Exception ex )
            {
                _logger.LogError( ex, "An error occurred while monitoring interfaces." );
            }

            await Task.Delay( 5000, stoppingToken ); // Wait for 5 seconds before the next check
        }
    }

    private async Task MonitorInterfacesAsync( List<NetworkInterfaceConfig> interfaces, string[] failoverCommands, string[] primaryCommands, CancellationToken stoppingToken )
    {
        int currentInterfaceIndex = 0;
        bool isFailoverActive = false; // Track if failover is active

        var currentInterface = interfaces[ currentInterfaceIndex ];
        bool allIPsFailed = true;

        _logger.LogInformation( "Monitoring interface: {Interface}", currentInterface.InterfaceName );

        // Ping all IPs concurrently using Task.WhenAll
        var pingTasks = currentInterface.MonitorIPs
            .Select( ip => PingThroughInterfaceAsync( ip, currentInterface.InterfaceName, stoppingToken ) )
            .ToArray();

        bool[] pingResults = await Task.WhenAll( pingTasks ); // Await all ping tasks

        for ( int i = 0; i < pingResults.Length; i++ )
        {
            if ( pingResults[ i ] )
            {
                _logger.LogInformation( "Ping to {IP} succeeded.", currentInterface.MonitorIPs[ i ] );
                allIPsFailed = false;
            }
            else
            {
                _logger.LogWarning( "Ping to {IP} failed.", currentInterface.MonitorIPs[ i ] );
            }
        }

        if ( allIPsFailed )
        {
            if ( !isFailoverActive )
            {
                _logger.LogError( "All IPs failed on interface {Interface}. Executing failover commands...", currentInterface.InterfaceName );
                await ExecuteBashCommandsAsync( failoverCommands, stoppingToken );

                // Switch to the next interface
                currentInterfaceIndex = ( currentInterfaceIndex + 1 ) % interfaces.Count;
                _logger.LogInformation( "Switched to interface: {Interface}", interfaces[ currentInterfaceIndex ].InterfaceName );
                isFailoverActive = true; // Mark failover as active
            }
        }
        else if ( isFailoverActive )
        {
            // Check if the primary interface is back online
            var primaryInterface = interfaces[ 0 ]; // Assuming the first interface is primary
            var primaryPingTasks = primaryInterface.MonitorIPs
                .Select( ip => PingThroughInterfaceAsync( ip, primaryInterface.InterfaceName, stoppingToken ) )
                .ToArray();

            bool[] primaryPingResults = await Task.WhenAll( primaryPingTasks ); // Await all primary ping tasks

            if ( primaryPingResults.All( result => result ) )
            {
                _logger.LogInformation( "Primary interface is back online. Switching back to primary interface..." );
                await ExecuteBashCommandsAsync( primaryCommands, stoppingToken );

                // Switch back to the primary interface
                currentInterfaceIndex = 0;
                _logger.LogInformation( "Switched back to primary interface: {Interface}", primaryInterface.InterfaceName );
                isFailoverActive = false; // Mark failover as inactive
            }
        }
    }

    private async Task<bool> PingThroughInterfaceAsync( string ipAddress, string interfaceName, CancellationToken stoppingToken )
    {
        Process process = null;
        try
        {
            process = new Process();
            process.StartInfo.FileName = "ping";
            process.StartInfo.Arguments = $"-c 1 -I {interfaceName} {ipAddress}"; // -c 1 sends 1 packet
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;

            process.Start();
            await process.WaitForExitAsync( stoppingToken ); // Wait asynchronously for the process to exit

            // Check the exit code (0 means success)
            bool isSuccess = process.ExitCode == 0;

            if ( isSuccess )
            {
                _logger.LogInformation( "Ping to {IP} through {Interface} succeeded.", ipAddress, interfaceName );
            }
            else
            {
                _logger.LogWarning( "Ping to {IP} through {Interface} failed.", ipAddress, interfaceName );
            }

            return isSuccess;
        }
        catch ( Exception ex )
        {
            _logger.LogError( ex, "Failed to ping {IP} through {Interface}.", ipAddress, interfaceName );
            return false;
        }
        finally
        {
            process?.Dispose(); // Ensure the process is disposed
        }
    }

    private async Task ExecuteBashCommandsAsync( string[] commands, CancellationToken stoppingToken )
    {
        foreach ( var command in commands )
        {
            Process process = null;
            try
            {
                process = new Process();
                process.StartInfo.FileName = "/bin/bash";
                process.StartInfo.Arguments = $"-c \"{command}\"";
                process.StartInfo.RedirectStandardOutput = true;
                process.StartInfo.RedirectStandardError = true;
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;

                process.Start();
                await process.WaitForExitAsync( stoppingToken ); // Wait asynchronously for the process to exit

                string output = await process.StandardOutput.ReadToEndAsync();
                _logger.LogInformation( "Executed command: {Command}. Output: {Output}", command, output );
            }
            catch ( Exception ex )
            {
                _logger.LogError( ex, "Failed to execute command: {Command}.", command );
            }
            finally
            {
                process?.Dispose(); // Ensure the process is disposed
            }
        }
    }
}