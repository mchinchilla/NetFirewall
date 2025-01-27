using NetFirewall.WanMonitor;
using Serilog;
using Serilog.Configuration;
using Serilog.Events;

internal class Program
{
    public static async Task Main( string[] args )
    {
        
        IConfiguration configuration = new ConfigurationBuilder()
            .SetBasePath( Directory.GetCurrentDirectory() )
            .AddJsonFile( "appsettings.json", optional: false, reloadOnChange: true )
            .Build();
        
        var host = Host.CreateDefaultBuilder( args )
            .ConfigureServices( ( hostContext, services ) =>
            {
                services.AddLogging( loggingBuilder => loggingBuilder.AddSerilog( dispose: true ) );
                services.AddHostedService<WanMonitorService>();
            } )
            .ConfigureAppConfiguration( ( hostingContext, config ) => { config.AddJsonFile( "appsettings.json", optional: false, reloadOnChange: true ); } )
            .UseSerilog( ( context, loggerConfiguration ) =>
            {
                loggerConfiguration.MinimumLevel.Debug();
                loggerConfiguration.MinimumLevel.Override( "Microsoft", LogEventLevel.Information );
                loggerConfiguration.Enrich.FromLogContext();
                loggerConfiguration.WriteTo.Console();
                loggerConfiguration.WriteTo.File( "logs/wan_monitor.log", rollingInterval: RollingInterval.Day );
            })
            .UseSerilog( ( context, loggerConfiguration ) =>
            {
                loggerConfiguration.MinimumLevel.Debug();
                loggerConfiguration.MinimumLevel.Override( "Microsoft", LogEventLevel.Information );
                loggerConfiguration.Enrich.FromLogContext();
                loggerConfiguration.WriteTo.Console();
                loggerConfiguration.WriteTo.File( "logs/wan_monitor_.log", rollingInterval: RollingInterval.Day );
            })
            .UseSystemd()
            .Build();

        await host.RunAsync();
    }
}