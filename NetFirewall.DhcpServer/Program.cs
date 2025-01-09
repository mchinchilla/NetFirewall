using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using Npgsql;
using RepoDb;
using Serilog.Configuration;

namespace NetFirewall.DhcpServer;

class Program
{
    static async Task Main( string[] args )
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .SetBasePath( Directory.GetCurrentDirectory() )
            .AddJsonFile( "appsettings.json", optional: false, reloadOnChange: true )
            .Build();

        Log.Logger = new LoggerConfiguration()
            .ReadFrom.Configuration( configuration )
            .CreateLogger();

        GlobalConfiguration
            .Setup()
            .UsePostgreSql();

        string? connectionString = configuration.GetConnectionString( "DefaultConnection" ) ?? "Host=localhost;Username=developer;Password=developer;Database=net_firewall;";

        try
        {
            var host = Host.CreateDefaultBuilder( args )
                .ConfigureAppConfiguration( ( context, config ) => { config.AddJsonFile( "appsettings.json", optional: true, reloadOnChange: true ); } )
                .UseSystemd()
                .ConfigureServices( ( hostContext, services ) =>
                {
                    var config = hostContext.Configuration;

                    /* Other */
                    services.Configure<DhcpConfig>( config.GetSection( "DhcpConfig" ) );
                    services.AddLogging( loggingBuilder => loggingBuilder.AddSerilog( dispose: true ) );
                    services.AddHostedService<DhcpWorker>();

                    /* Singleton */
                    services.AddSingleton( new NpgsqlConnection( connectionString ) );
                    services.AddSingleton<string>( connectionString );

                    /* Transient */
                    services.AddTransient<IDhcpServerService, DhcpServerService>();
                    services.AddTransient<IDhcpLeasesService, DhcpLeasesService>();
                } )
                .UseSerilog()
                .Build();

            await host.RunAsync();
        }
        catch ( Exception ex )
        {
            Log.Fatal( $"A fatal error occurred starting the DHCP server: {ex.Message}" );
        }
        finally
        {
            Log.CloseAndFlush();
        }
    }
}