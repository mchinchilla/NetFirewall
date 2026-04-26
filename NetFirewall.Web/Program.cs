using NetFirewall.Models.System;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Services.Processes;
using NetFirewall.Web.Filters;
using Npgsql;
using RepoDb;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseSerilog((context, services, configuration) =>
    configuration
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services));

builder.AddServiceDefaults();

// ----- MVC + global filters -----
builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add<ValidationToServiceResponseFilter>();
});

// HTMX requests can't send the form-field anti-forgery token, so accept it via header instead.
// site.js attaches it on every request from a meta tag rendered in _Layout.
builder.Services.AddAntiforgery(o => o.HeaderName = "RequestVerificationToken");

// ----- Database -----
GlobalConfiguration.Setup().UsePostgreSql();

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
                       ?? throw new InvalidOperationException(
                           "ConnectionStrings:DefaultConnection is not configured.");

var dataSourceBuilder = new NpgsqlDataSourceBuilder(connectionString);
builder.Services.AddSingleton(dataSourceBuilder.Build());

// ----- Process runner (rule #8 — every shell-out goes through DI) -----
builder.Services.AddSingleton<IProcessRunner, ProcessRunner>();

// ----- Domain services -----
builder.Services.AddSingleton<ILinuxDistroService, LinuxDistroService>();
builder.Services.AddScoped<IFirewallService, FirewallService>();

// ----- Network config writers (one per distro family, plus a NoOp fallback for dev) -----
builder.Services.AddKeyedSingleton<INetworkConfigService, DebianInterfacesConfigService>(NetworkConfigMethod.Interfaces);
builder.Services.AddKeyedSingleton<INetworkConfigService, NetplanConfigService>(NetworkConfigMethod.Netplan);
builder.Services.AddKeyedSingleton<INetworkConfigService, NetworkManagerConfigService>(NetworkConfigMethod.NetworkManager);
builder.Services.AddKeyedSingleton<INetworkConfigService, NoOpNetworkConfigService>(NetworkConfigMethod.Unknown);
builder.Services.AddSingleton<INetworkConfigResolver, NetworkConfigResolver>();
builder.Services.AddScoped<IStaticRouteApplicator, StaticRouteApplicator>();

var app = builder.Build();

app.UseSerilogRequestLogging();
app.MapDefaultEndpoints();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseRouting();
app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

app.Run();
