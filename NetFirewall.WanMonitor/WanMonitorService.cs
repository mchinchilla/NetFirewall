using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NetFirewall.Models;

namespace NetFirewall.WanMonitor;

public class WanMonitorService : BackgroundService
{
    private readonly ILogger<WanMonitorService> _logger;
    private readonly IConfiguration _configuration;
    private readonly List<NetworkInterfaceConfig>? _networkInterfaceConfig;
    private readonly NetworkInterfaceConfig _primaryInterface;
    private readonly NetworkInterfaceConfig _secondaryInterface; 
    private readonly int _checkInterval;
    private readonly string? _primaryInterfaceName;
    private readonly string? _secondaryInterfaceName;
    private readonly string? _primaryGateway;
    private readonly string? _secondaryGateway;
    private readonly List<string>? _primaryIPs;
    private readonly List<string>? _secondaryIPs;
    private readonly List<string>? _extraPrimaryCommands;
    private readonly List<string>? _extraSecondaryCommands;

    private string? _currentInterface;
    private string? _currentGateway;
    private List<string>? _currentIPs;
    private bool _isFailoverActive = false;
    


    public WanMonitorService( ILogger<WanMonitorService> logger, IConfiguration configuration )
    {
        _logger = logger;
        _configuration = configuration;

        try
        {
            _checkInterval = _configuration.GetValue<int?>( "AppConfig:CheckInterval" ) ?? 30;
            _networkInterfaceConfig = _configuration.GetSection( "Network" ).Get<List<NetworkInterfaceConfig>>();
            if ( _networkInterfaceConfig == null || _networkInterfaceConfig.Count == 0 )
            {
                throw new Exception( $"There is no network configuration." );
            }

            _primaryInterface = _networkInterfaceConfig.FirstOrDefault( x => x.IsPrimary ) ?? throw new Exception( $"Primary interface is not configured." );
            _primaryInterfaceName = _networkInterfaceConfig.FirstOrDefault( x => x.IsPrimary )?.InterfaceName;
            _primaryGateway = _networkInterfaceConfig.FirstOrDefault( x => x.IsPrimary )?.InterfaceGateway;
            _primaryIPs = _networkInterfaceConfig.FirstOrDefault( x => x.IsPrimary )?.MonitorIPs;

            _secondaryInterface = _networkInterfaceConfig.FirstOrDefault( x => !x.IsPrimary ) ?? throw new Exception( $"Secondary interface is not configured." );
            _secondaryInterfaceName = _networkInterfaceConfig.FirstOrDefault( x => !x.IsPrimary )?.InterfaceName;
            _secondaryGateway = _networkInterfaceConfig.FirstOrDefault( x => !x.IsPrimary )?.InterfaceGateway;
            _secondaryIPs = _networkInterfaceConfig.FirstOrDefault( x => !x.IsPrimary )?.MonitorIPs;

            var bashCommandsConfig = _configuration.GetSection( "BashCommands" ).Get<BashCommandsConfig>();
            _extraPrimaryCommands = bashCommandsConfig?.ExtraPrimaryCommands ?? new List<string>();
            _extraSecondaryCommands = bashCommandsConfig?.ExtraSecondaryCommands ?? new List<string>();
            
            foreach ( var command in bashCommandsConfig.ExtraPrimaryCommands )
            {
                _logger.LogInformation( $"Extra Primary Command: {command}" );
            }

            foreach ( var VARIABLE in bashCommandsConfig.ExtraSecondaryCommands )
            {
                _logger.LogInformation( $"Extra Secondary Command: {VARIABLE}" );
            }
            
            _logger.LogInformation( "WAN Monitor Worker Service configuration loaded successfully." );
        }
        catch ( Exception exc )
        {
            _logger.LogError( $"{exc.Message}" );
            throw new Exception( $"{exc.Message}" );
        }
    }

    protected override async Task ExecuteAsync( CancellationToken stoppingToken )
    {
        _logger.LogInformation( "WAN Monitor Worker Service started." );
        _logger.LogInformation( $"".PadRight( 40, '=' ) );
        _logger.LogInformation( $"Primary Interface: {_primaryInterfaceName}" );
        _logger.LogInformation( $"Primary Gateway: {_primaryGateway}" );
        _logger.LogInformation( $"Primary IPs: {string.Join( ", ", _primaryIPs )}" );

        _logger.LogInformation( $"".PadRight( 40, '-' ) );

        _logger.LogInformation( $"Secondary Interface: {_secondaryInterfaceName}" );
        _logger.LogInformation( $"Secondary Gateway: {_secondaryGateway}" );
        _logger.LogInformation( $"Secondary IPs: {string.Join( ", ", _secondaryIPs )}" );

        _logger.LogInformation( $"".PadRight( 40, '-' ) );

        _logger.LogInformation( $"Check Interval: {_checkInterval} secs" );

        _logger.LogInformation( $"".PadRight( 40, '=' ) );


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
                InterfaceName = _primaryInterfaceName, // Primary interface
                MonitorIPs = _primaryIPs,
                InterfaceGateway = _primaryGateway,
            },
            new NetworkInterfaceConfig
            {
                InterfaceName = _secondaryInterfaceName, // Backup interface
                MonitorIPs = _secondaryIPs,
                InterfaceGateway = _secondaryGateway,
            }
        };

        // Bash commands to execute when failover occurs
        var failoverCommandsList = new List<string>
        {
            "echo 'Switching to backup interface'",
            $"echo 'ip route replace default via {_secondaryGateway} dev {_secondaryInterfaceName}'"
        };
        if ( _extraSecondaryCommands != null && _extraSecondaryCommands.Count > 0 )
        {
            failoverCommandsList.AddRange( _extraSecondaryCommands );
        }
        string[] failoverCommands = failoverCommandsList.ToArray();

        // Bash commands to execute when primary interface is back online
        var primaryCommandsList = new List<string>
        {
            "echo 'Switching to primary interface'",
            $"echo 'ip route replace default via {_primaryGateway} dev {_primaryInterfaceName}'"
        };
        if ( _extraPrimaryCommands != null && _extraPrimaryCommands.Count > 0 )
        {
            primaryCommandsList.AddRange( _extraPrimaryCommands );
        }
        string[] primaryCommands = primaryCommandsList.ToArray();

        _logger.LogInformation( "Executing primary commands on service startup..." );
        await ExecuteBashCommandsAsync( primaryCommands, stoppingToken );
        _logger.LogInformation( "Primary commands executed successfully." );

        while ( !stoppingToken.IsCancellationRequested )
        {
            try
            {
                await MonitorInterfacesAsync( interfaces, failoverCommands, primaryCommands, stoppingToken );
            }
            catch ( Exception ex )
            {
                _logger.LogError( ex, "An error occurred while monitoring interfaces." );
            }
            finally
            {
                _logger.LogInformation( $"Monitoring completed ... wait {_checkInterval} secs" );
                await Task.Delay( ( _checkInterval * 1000 ), stoppingToken );
            }
        }
    }

    private async Task MonitorInterfacesAsync( List<NetworkInterfaceConfig> interfaces, string[] failoverCommands, string[] primaryCommands, CancellationToken stoppingToken )
    {
        int currentInterfaceIndex = 0;

        var currentInterface = interfaces[ currentInterfaceIndex ];
        bool allIPsFailed = true;

        _logger.LogInformation( $"Monitoring interface: {currentInterface.InterfaceName}, FailoverActive: {_isFailoverActive}" );

        // Ping all IPs concurrently using Task.WhenAll
        var pingTasks = currentInterface.MonitorIPs!
            .Select( ip => PingThroughInterfaceAsync( ip, currentInterface.InterfaceName, stoppingToken ) )
            .ToArray();

        bool[] pingResults = await Task.WhenAll( pingTasks ); // Await all ping tasks

        for ( int i = 0; i < pingResults.Length; i++ )
        {
            if ( pingResults[ i ] )
            {
                _logger.LogInformation( $"Ping to {currentInterface.MonitorIPs![ i ]} succeeded." );
                allIPsFailed = false;
            }
            else
            {
                _logger.LogWarning( $"Ping to {currentInterface.MonitorIPs![ i ]} failed." );
            }
        }

        if ( allIPsFailed )
        {
            if ( !_isFailoverActive )
            {
                _logger.LogWarning( "All IPs failed on interface {Interface}. Executing failover commands...", currentInterface.InterfaceName );
                await ExecuteBashCommandsAsync( failoverCommands, stoppingToken );

                // Switch to the next interface
                currentInterfaceIndex = ( currentInterfaceIndex + 1 ) % interfaces.Count;
                _logger.LogInformation( "Switched to interface: {Interface}", interfaces[ currentInterfaceIndex ].InterfaceName );
                _isFailoverActive = true;
            }
        }
        else if ( _isFailoverActive )
        {
            // Check if the primary interface is back online
            var primaryInterface = _primaryInterface;
            var primaryPingTasks = primaryInterface.MonitorIPs!
                .Select( ip => PingThroughInterfaceAsync( ip, primaryInterface.InterfaceName, stoppingToken ) )
                .ToArray();

            bool[] primaryPingResults = await Task.WhenAll( primaryPingTasks ); // Await all primary ping tasks

            if ( primaryPingResults.All( result => result ) )
            {
                _logger.LogInformation( "Primary interface is back online. Switching back to primary interface..." );
                await ExecuteBashCommandsAsync( primaryCommands, stoppingToken );

                // Switch back to the primary interface
                currentInterfaceIndex = _networkInterfaceConfig!.IndexOf( _primaryInterface );
                _logger.LogInformation( "Switched back to primary interface: {Interface}", primaryInterface.InterfaceName );
                _isFailoverActive = false; // Mark failover as inactive
            }
        }
    }

    private async Task<bool> PingThroughInterfaceAsync( string ipAddress, string? interfaceName, CancellationToken stoppingToken )
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
            _logger.LogInformation(  $"Executing command: {command}" );
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
                
                _logger.LogInformation( $"Ready to execute the command: {command}" );
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