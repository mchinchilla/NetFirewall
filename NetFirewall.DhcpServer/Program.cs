using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Serilog;
using System.Net;
using System.Net.Sockets;
using NetFirewall.Services.Dhcp;
using Npgsql;

namespace NetFirewall.DhcpServer;

class Program
{
    static async Task Main( string[] args )
    {
        Log.Logger = new LoggerConfiguration()
            .WriteTo.Console()
            .WriteTo.File( "logs/dhcp_server.log" )
            .CreateLogger();

        var configuration = new ConfigurationBuilder()
            .SetBasePath( Directory.GetCurrentDirectory() )
            .AddJsonFile( "appsettings.json" )
            .Build();

        string? connectionString = configuration.GetConnectionString( "DefaultConnection" ) ?? "Host=localhost;Username=postgres;Password=1Nframund02023!;Database=net_firewall;";

        try
        {
            await Host.CreateDefaultBuilder( args )
                .UseSystemd()
                .ConfigureServices( ( hostContext, services ) =>
                {
                    /* Other */
                    services.AddHostedService<Worker>();
                    services.AddLogging( loggingBuilder => loggingBuilder.AddSerilog( dispose: true ) );
                    
                    /* Singleton */
                    services.AddSingleton( new NpgsqlConnection( connectionString ) );
                    services.AddSingleton<string>( connectionString );
                    
                    /* Transient */
                    services.AddTransient<IDhcpServerService, DhcpServerService>();
                    services.AddTransient<IDhcpConfigService, DhcpConfigService>();
                    services.AddTransient<IDhcpLeasesService, DhcpLeasesService>();
                    services.AddTransient<IDdnsService, DdnsService>();
                    
                } )
                .Build()
                .RunAsync();
        }
        catch ( Exception ex )
        {
            Log.Fatal( $"A fatal error occurred starting the DHCP server: {ex.Message}" );
        }
        finally
        {
            await Log.CloseAndFlushAsync();
        }
    }
}