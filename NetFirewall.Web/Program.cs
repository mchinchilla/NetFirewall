using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Authorization;
using NetFirewall.Models.System;
using NetFirewall.Services.Auth;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Services.Processes;
using NetFirewall.Web.Auth;
using NetFirewall.Web.Auth.Bootstrap;
using NetFirewall.Web.Daemon;
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

// ----- MVC + global filters + global [Authorize] -----
builder.Services.AddControllersWithViews(options =>
{
    options.Filters.Add<ValidationToServiceResponseFilter>();

    // Default policy: every endpoint requires an authenticated session.
    // Public endpoints (login, bootstrap, error) opt out via [AllowAnonymous].
    var policy = new AuthorizationPolicyBuilder(SessionCookieAuthHandler.SchemeName)
        .RequireAuthenticatedUser()
        .Build();
    options.Filters.Add(new AuthorizeFilter(policy));
});

// HTMX requests can't send the form-field anti-forgery token, so accept it via header.
builder.Services.AddAntiforgery(o => o.HeaderName = "RequestVerificationToken");

// ----- Authentication: custom session-cookie scheme (no Identity, no JWT). -----
builder.Services
    .AddAuthentication(SessionCookieAuthHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, SessionCookieAuthHandler>(
        SessionCookieAuthHandler.SchemeName, _ => { });
builder.Services.AddAuthorization();

// ----- Database -----
GlobalConfiguration.Setup().UsePostgreSql();

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
                       ?? throw new InvalidOperationException(
                           "ConnectionStrings:DefaultConnection is not configured.");

var dataSourceBuilder = new NpgsqlDataSourceBuilder(connectionString);
builder.Services.AddSingleton(dataSourceBuilder.Build());

// ----- Process runner (rule #8) -----
builder.Services.AddSingleton<IProcessRunner, ProcessRunner>();

// ----- Domain services -----
builder.Services.AddSingleton<ILinuxDistroService, LinuxDistroService>();
builder.Services.AddScoped<IFirewallService, FirewallService>();

// ----- Network config writers (each distro family + a NoOp) -----
// These are the LOW-LEVEL writers that actually shell out (Process.Start).
// When Daemon:Enabled = true they are NOT what controllers receive directly —
// they're wrapped inside DaemonNetworkConfigService which proxies to the daemon.
builder.Services.AddKeyedSingleton<INetworkConfigService, DebianInterfacesConfigService>(NetworkConfigMethod.Interfaces);
builder.Services.AddKeyedSingleton<INetworkConfigService, NetplanConfigService>(NetworkConfigMethod.Netplan);
builder.Services.AddKeyedSingleton<INetworkConfigService, NetworkManagerConfigService>(NetworkConfigMethod.NetworkManager);
builder.Services.AddKeyedSingleton<INetworkConfigService, NoOpNetworkConfigService>(NetworkConfigMethod.Unknown);

// Concrete resolver registered separately so the decorator can wrap it without Scrutor.
builder.Services.AddSingleton<NetworkConfigResolver>();

// ----- Daemon client + DI swap -----
builder.Services.AddHttpContextAccessor();
builder.Services.Configure<DaemonClientOptions>(builder.Configuration.GetSection(DaemonClientOptions.SectionName));
var daemonOpts = builder.Configuration.GetSection(DaemonClientOptions.SectionName).Get<DaemonClientOptions>() ?? new DaemonClientOptions();

if (daemonOpts.Enabled)
{
    // Daemon owns OS mutations. The Web's INetworkConfigResolver returns a
    // wrapper that proxies write ops over the Unix socket while keeping read
    // ops (preview / file path / validate) local — controllers stay unchanged.
    builder.Services.AddSingleton<IDaemonClient, DaemonClient>();
    builder.Services.AddScoped<IStaticRouteApplicator, DaemonStaticRouteApplicator>();
    builder.Services.AddSingleton<INetworkConfigResolver>(sp =>
        new DaemonResolverDecorator(sp.GetRequiredService<NetworkConfigResolver>(), sp));
}
else
{
    // Legacy path — Web shells out directly. Useful for local-only debugging.
    builder.Services.AddSingleton<INetworkConfigResolver>(sp => sp.GetRequiredService<NetworkConfigResolver>());
    builder.Services.AddScoped<IStaticRouteApplicator, StaticRouteApplicator>();
}

// ----- Auth services (rule #8: every process is DI-registered) -----
builder.Services.AddSingleton<IPasswordHasher, Argon2PasswordHasher>();
builder.Services.AddSingleton<ITotpService, TotpService>();
builder.Services.AddSingleton<ITotpSecretCipher, AesGcmTotpSecretCipher>();
builder.Services.AddSingleton<IRecoveryCodeGenerator, RecoveryCodeGenerator>();

builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<ISessionService, SessionService>();
builder.Services.AddScoped<IUserTotpService, UserTotpService>();
builder.Services.AddScoped<IRecoveryCodeService, RecoveryCodeService>();
builder.Services.AddScoped<IAuthAuditService, AuthAuditService>();
builder.Services.AddScoped<ISessionCookieIssuer, SessionCookieIssuer>();
builder.Services.AddScoped<IPendingAuthTicket, PendingAuthTicket>();

// Bootstrap: holds the one-time admin-creation token; issuer is a hosted service.
builder.Services.AddSingleton<IBootstrapTokenStore, BootstrapTokenStore>();
builder.Services.AddHostedService<BootstrapTokenIssuer>();

// DHCP services. Subnet service is the cached singleton used by both the
// setup wizard and the DHCP admin pages. Admin facade is what controllers
// inject for full CRUD over subnets / pools / leases / reservations.
builder.Services.AddSingleton<NetFirewall.Services.Dhcp.IDhcpSubnetService, NetFirewall.Services.Dhcp.DhcpSubnetService>();
builder.Services.AddScoped<NetFirewall.Services.Dhcp.IDhcpAdminService, NetFirewall.Services.Dhcp.DhcpAdminService>();

// Setup wizard.
builder.Services.AddScoped<NetFirewall.Services.Setup.ISetupWizardService, NetFirewall.Services.Setup.SetupWizardService>();

// Runtime metadata for the login system-info card.
builder.Services.AddSingleton<IAppInfoService, AppInfoService>();

// Read-only catalog of /Bash reference scripts (nftables conf, rt_tables, etc).
builder.Services.Configure<NetFirewall.Web.Services.BashScriptCatalogOptions>(
    builder.Configuration.GetSection("BashCatalog"));
builder.Services.AddSingleton<NetFirewall.Web.Services.IBashScriptCatalog,
                              NetFirewall.Web.Services.BashScriptCatalog>();

// Runtime-tunable settings (key/value backed by app_settings, in-memory cached).
builder.Services.AddSingleton<NetFirewall.Web.Services.IAppSettingsService,
                              NetFirewall.Web.Services.AppSettingsService>();

// System monitoring: singleton because the implementation caches per-CPU
// jiffies between calls to compute usage% deltas correctly. The Web only
// READS metrics (live snapshot + historical query); the daemon is what
// runs the collector and writes samples to system_metrics_*.
builder.Services.AddSingleton<NetFirewall.Services.Monitoring.ISystemMonitorService,
                              NetFirewall.Services.Monitoring.SystemMonitorService>();
builder.Services.AddScoped<NetFirewall.Services.Monitoring.IMetricsQueryService,
                           NetFirewall.Services.Monitoring.MetricsQueryService>();

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

// Auth must run after routing so authorization sees the matched endpoint.
app.UseAuthentication();
app.UseAuthorization();

app.MapStaticAssets();

app.MapControllerRoute(
        name: "default",
        pattern: "{controller=Home}/{action=Index}/{id?}")
    .WithStaticAssets();

app.Run();
