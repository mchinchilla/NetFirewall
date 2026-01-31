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
    static async Task Main(string[] args)
    {
        IConfiguration configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .Build();

        Log.Logger = new LoggerConfiguration()
            .ReadFrom.Configuration(configuration)
            .CreateLogger();

        GlobalConfiguration
            .Setup()
            .UsePostgreSql();

        string? connectionString = configuration.GetConnectionString("DefaultConnection")
            ?? "Host=localhost;Username=developer;Password=developer;Database=net_firewall;";

        try
        {
            var host = Host.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((context, config) =>
                {
                    config.AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);
                })
                .UseSystemd()
                .ConfigureServices((hostContext, services) =>
                {
                    var config = hostContext.Configuration;

                    /* Configuration */
                    services.Configure<DhcpConfig>(config.GetSection("DhcpConfig"));
                    services.AddLogging(loggingBuilder => loggingBuilder.AddSerilog(dispose: true));

                    /* Database - Use NpgsqlDataSource for proper connection pooling */
                    var dataSourceBuilder = new NpgsqlDataSourceBuilder(connectionString);
                    var dataSource = dataSourceBuilder.Build();
                    services.AddSingleton(dataSource);

                    /* High-Performance Lease Cache - Singleton with warmup
                     * Reduces DB roundtrips by ~90% for read operations
                     * Write-through ensures durability with PostgreSQL */
                    services.AddSingleton<LeaseCache>();

                    /* Services - Scoped for per-request lifecycle */
                    services.AddScoped<IDhcpServerService, DhcpServerService>();
                    services.AddScoped<IDdnsService, DdnsService>();
                    services.AddScoped<IDhcpLeasesService, DhcpLeasesService>();
                    services.AddScoped<IDhcpSubnetService, DhcpSubnetService>();

                    /* Failover - Singleton for persistent connection to peer */
                    services.AddSingleton<IFailoverService, FailoverService>();

                    /* DHCP Worker - Hosted service (starts after cache warmup) */
                    services.AddHostedService<DhcpWorker>();
                })
                .UseSerilog()
                .Build();

            // Warm up the lease cache before starting DHCP worker
            var leaseCache = host.Services.GetRequiredService<LeaseCache>();
            await leaseCache.WarmupAsync();

            // Start the failover service
            var failoverService = host.Services.GetRequiredService<IFailoverService>();
            await failoverService.StartAsync();

            await host.RunAsync();
        }
        catch (Exception ex)
        {
            Log.Fatal(ex, "A fatal error occurred starting the DHCP server");
        }
        finally
        {
            Log.CloseAndFlush();
        }
    }
}
