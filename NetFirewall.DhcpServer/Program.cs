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
        // Environment variables LAST so the systemd EnvironmentFile (dhcp.env) can
        // override appsettings.json — e.g. ConnectionStrings__DefaultConnection and
        // DHCP__Interface. Without this, the connection string read below would ignore
        // dhcp.env and use the password baked into the published appsettings.json.
        IConfiguration configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
            .AddEnvironmentVariables()
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
            // CreateDefaultBuilder already loads appsettings.json, appsettings.{env}.json and
            // THEN the environment. Adding appsettings.json again here put the JSON after the
            // environment, so dhcp.env (DHCP__Interface, …) was silently ignored and the server
            // bound the baked-in default interface (found by the Debian 13 end-to-end install).
            var host = Host.CreateDefaultBuilder(args)
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
                    // Reservations from memory on the hot path; dropped by the reservation.changed NOTIFY.
                    services.AddSingleton<IDhcpReservationCache, DhcpReservationCache>();

                    /* Services */
                    services.AddScoped<IDhcpServerService, DhcpServerService>();
                    // This host's interface addresses → the server identifier (option 54) per reply.
                    services.AddSingleton<IInterfaceAddressProvider, InterfaceAddressProvider>();
                    services.AddScoped<IDdnsService, DdnsService>();
                    services.AddScoped<IDhcpLeasesService, DhcpLeasesService>();

                    /* Subnet Service - Singleton to maintain cache across requests */
                    services.AddSingleton<IDhcpSubnetService, DhcpSubnetService>();

                    /* Cache invalidation listener - LISTENs on Postgres channel
                     * for NOTIFYs sent by the Web on subnet/pool/exclusion writes,
                     * drops the in-process subnet cache so the next lookup refetches. */
                    services.AddHostedService<DhcpCacheRefreshListener>();

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
            // Non-zero so systemd treats it as a failure (Restart=on-failure, `systemctl status`
            // shows it red) instead of "Deactivated successfully".
            Environment.ExitCode = 1;
        }
        finally
        {
            Log.CloseAndFlush();
        }
    }
}
