using NetFirewall.Services.Dhcp;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Monitoring;
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

// Add DHCP Admin services
builder.Services.AddScoped<IDhcpAdminService, DhcpAdminService>();

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