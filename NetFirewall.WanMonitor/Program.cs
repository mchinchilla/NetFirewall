using NetFirewall.WanMonitor;

internal class Program
{
    public static async Task Main( string[] args )
    {
        var host = Host.CreateDefaultBuilder( args )
            .ConfigureServices( ( hostContext, services ) => { services.AddHostedService<WanMonitorService>(); } )
            .ConfigureAppConfiguration( ( hostingContext, config ) => { config.AddJsonFile( "appsettings.json", optional: false, reloadOnChange: true ); } )
            .UseSystemd()
            .Build();

        await host.RunAsync();
    }
}