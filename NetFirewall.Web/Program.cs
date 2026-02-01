using NetFirewall.Models.System;
using NetFirewall.Services.Dhcp;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Monitoring;
using NetFirewall.Services.Network;
using NetFirewall.Web.Components;
using Npgsql;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

// Add Blazor Server services
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// Add database connection
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
    ?? "Host=localhost;Username=developer;Password=developer;Database=net_firewall;";

var dataSourceBuilder = new NpgsqlDataSourceBuilder(connectionString);
var dataSource = dataSourceBuilder.Build();
builder.Services.AddSingleton(dataSource);

// Add Firewall services
builder.Services.Configure<NftApplyOptions>(builder.Configuration.GetSection("NftApply"));
builder.Services.AddScoped<IFirewallService, FirewallService>();
builder.Services.AddScoped<INftApplyService, NftApplyService>();

// Add Linux Distro and Network Config services
builder.Services.AddSingleton<ILinuxDistroService, LinuxDistroService>();
builder.Services.AddScoped<NetplanConfigService>();
builder.Services.AddScoped<DebianInterfacesConfigService>();

// Factory that selects the correct network config service based on detected distro
builder.Services.AddScoped<INetworkConfigService>(sp =>
{
    var distroService = sp.GetRequiredService<ILinuxDistroService>();
    var info = distroService.DetectDistributionAsync().GetAwaiter().GetResult();

    return info.ConfigMethod switch
    {
        NetworkConfigMethod.Netplan => sp.GetRequiredService<NetplanConfigService>(),
        NetworkConfigMethod.Interfaces => sp.GetRequiredService<DebianInterfacesConfigService>(),
        // Default to Netplan for unknown (will work for development on non-Linux)
        _ => sp.GetRequiredService<NetplanConfigService>()
    };
});

// Add DHCP services
builder.Services.AddScoped<IDhcpAdminService, DhcpAdminService>();
builder.Services.AddScoped<IDhcpLeasesService, DhcpLeasesService>();

// Add System Monitor service (singleton for state tracking)
builder.Services.AddSingleton<ISystemMonitorService, SystemMonitorService>();

// Add Metrics Query service for historical data
builder.Services.AddScoped<IMetricsQueryService, MetricsQueryService>();

// Add Metrics Collector background service
builder.Services.Configure<MetricsCollectorOptions>(
    builder.Configuration.GetSection("MetricsCollector"));
builder.Services.AddHostedService<MetricsCollectorService>();

var app = builder.Build();

app.MapDefaultEndpoints();

// Configure the HTTP request pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseAntiforgery();

app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

await app.RunAsync();