using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Mvc.Authorization;
using NetFirewall.Models.System;
using NetFirewall.Services.Auth;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Services.Processes;
using NetFirewall.Web.Auth;
using NetFirewall.Web.Auth.Bootstrap;
using NetFirewall.Services.Daemon;
using NetFirewall.Web.Daemon;
using NetFirewall.Web.Filters;
using Npgsql;
using RepoDb;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// systemd integration: sends sd_notify READY=1 once Kestrel is listening,
// satisfying the Type=notify unit. No-op on non-systemd hosts.
builder.Host.UseSystemd();

builder.Host.UseSerilog((context, services, configuration) =>
    configuration
        .ReadFrom.Configuration(context.Configuration)
        .ReadFrom.Services(services));

builder.AddServiceDefaults();

// DataProtection keys go to a persistent dir so sessions survive a Web
// restart. systemd's StateDirectory= (netfirewall/web) creates the parent
// owned by the netfirewall-web user; we just nest "keys" under it. Without
// this, ASP.NET falls back to an in-memory key ring and every restart
// invalidates session cookies + antiforgery tokens.
//
// The DataProtectionKeysDir env var (set in /etc/netfirewall/web.env) lets
// the install location override this; default keeps dev simple.
{
    var keysDir = builder.Configuration["DataProtectionKeysDir"]
                  ?? (builder.Environment.IsProduction()
                      ? "/var/lib/netfirewall/web/keys"
                      : Path.Combine(builder.Environment.ContentRootPath, ".dp-keys"));
    Directory.CreateDirectory(keysDir);
    builder.Services.AddDataProtection()
        .PersistKeysToFileSystem(new DirectoryInfo(keysDir))
        .SetApplicationName("NetFirewall.Web");
}

// Behind nginx on loopback: trust X-Forwarded-For / X-Forwarded-Proto so
// audit logs and the "System info" card show the real client IP instead of
// 127.0.0.1. KnownNetworks default already includes loopback. Activated via
// app.UseForwardedHeaders() in the pipeline below.
builder.Services.Configure<Microsoft.AspNetCore.Builder.ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders =
        Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedFor
        | Microsoft.AspNetCore.HttpOverrides.ForwardedHeaders.XForwardedProto;
});

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

// All four daemon-vs-local DI swaps live in one extension method. Pinned by
// DaemonServiceCollectionExtensionsTests in the Tests project — modify both
// when adding a new daemon-aware service.
builder.Services.AddDaemonClientAndCiphers(daemonOpts);

// ----- Auth services (rule #8: every process is DI-registered) -----
builder.Services.AddSingleton<IPasswordHasher, Argon2PasswordHasher>();
builder.Services.AddSingleton<ITotpService, TotpService>();
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

// WireGuard — Web reads/writes catalog, posts privileged ops to daemon
// (key gen + apply + status all live behind /v1/wireguard/*).
builder.Services.AddScoped<NetFirewall.Services.Vpn.IWireGuardService,
                           NetFirewall.Services.Vpn.WireGuardService>();
builder.Services.AddSingleton<NetFirewall.Services.Vpn.IWireGuardConfigService,
                              NetFirewall.Services.Vpn.WireGuardConfigService>();
// Bridges WireGuard ↔ policy-routing/firewall rows (egress device routing,
// auto routing scaffold, per-peer NAT/forward). Scoped — pure DB writes via
// IFirewallService + IPolicyRoutingService.
builder.Services.AddScoped<NetFirewall.Services.Vpn.IVpnRoutingService,
                           NetFirewall.Services.Vpn.VpnRoutingService>();

// Network objects — alias-style address objects. Filter / NAT / mangle
// generators resolve names → flat CIDRs through INetworkObjectResolver.
builder.Services.AddScoped<NetFirewall.Services.Network.INetworkObjectService,
                           NetFirewall.Services.Network.NetworkObjectService>();
builder.Services.AddScoped<NetFirewall.Services.Network.INetworkObjectResolver,
                           NetFirewall.Services.Network.NetworkObjectResolver>();

// Network services — named L4 catalog (SSH=tcp/22, RTP=udp/10000-20000, …).
// Filter/mangle/PF generators resolve service names → port specs at apply time.
builder.Services.AddScoped<NetFirewall.Services.Network.INetworkServiceService,
                           NetFirewall.Services.Network.NetworkServiceService>();
builder.Services.AddScoped<NetFirewall.Services.Network.INetworkServiceResolver,
                           NetFirewall.Services.Network.NetworkServiceResolver>();

// Full-text search — Postgres tsvector + GIN, fed by per-source triggers.
builder.Services.AddScoped<NetFirewall.Services.Search.ISearchService,
                           NetFirewall.Services.Search.SearchService>();

// Time-based filter rules — schedules attach to filter rules; daemon's
// watcher service (registered in daemon) triggers nft re-apply on transition.
builder.Services.AddScoped<NetFirewall.Services.Firewall.IScheduleService,
                           NetFirewall.Services.Firewall.ScheduleService>();

// DHCP services. Subnet service is the cached singleton used by both the
// setup wizard and the DHCP admin pages. Admin facade is what controllers
// inject for full CRUD over subnets / pools / leases / reservations.
builder.Services.AddSingleton<NetFirewall.Services.Dhcp.IDhcpSubnetService, NetFirewall.Services.Dhcp.DhcpSubnetService>();
builder.Services.AddScoped<NetFirewall.Services.Dhcp.IDhcpAdminService, NetFirewall.Services.Dhcp.DhcpAdminService>();

// Cache invalidation notifier — Web emits NOTIFY on subnet/pool/exclusion writes
// so the DhcpServer process can drop its in-process cache immediately instead of
// waiting up to 5 minutes for TTL.
builder.Services.AddSingleton<NetFirewall.Services.Dhcp.IDhcpCacheNotifier, NetFirewall.Services.Dhcp.DhcpCacheNotifier>();

// Setup wizard.
builder.Services.AddScoped<NetFirewall.Services.Setup.ISetupWizardService, NetFirewall.Services.Setup.SetupWizardService>();

// Runtime metadata for the login system-info card.
builder.Services.AddSingleton<IAppInfoService, AppInfoService>();

// On-demand GeoIP/ASN enrichment for the login + signed-in cards. Reuses the
// same named HttpClient + config section as the background IpAsnResolver so the
// third-party-disclosure switch (IpAsnResolver:Enabled) governs both. In-memory
// cached, so MemoryCache must be available.
builder.Services.AddMemoryCache();
builder.Services.AddHttpClient(NetFirewall.Services.Monitoring.IpAsnResolver.HttpClientName);
builder.Services.Configure<NetFirewall.Services.Monitoring.IpAsnResolverOptions>(
    builder.Configuration.GetSection(NetFirewall.Services.Monitoring.IpAsnResolverOptions.SectionName));
builder.Services.AddSingleton<NetFirewall.Services.Monitoring.IGeoIpLookupService,
                              NetFirewall.Services.Monitoring.GeoIpLookupService>();

// Web terminal: relays the browser WebSocket to the daemon's root-PTY socket.
// Stateless; depends on the singleton IDaemonClient (which forwards the
// per-request session token via IHttpContextAccessor).
builder.Services.AddSingleton<NetFirewall.Web.Services.ITerminalProxyService,
                              NetFirewall.Web.Services.TerminalProxyService>();

// Read-only catalog of /Bash reference scripts (nftables conf, rt_tables, etc).
builder.Services.Configure<NetFirewall.Web.Services.BashScriptCatalogOptions>(
    builder.Configuration.GetSection("BashCatalog"));
builder.Services.AddSingleton<NetFirewall.Web.Services.IBashScriptCatalog,
                              NetFirewall.Web.Services.BashScriptCatalog>();

// Runtime-tunable settings (key/value backed by app_settings, in-memory cached).
builder.Services.AddSingleton<NetFirewall.Services.Settings.IAppSettingsService,
                              NetFirewall.Services.Settings.AppSettingsService>();

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

// Behind nginx (or any reverse proxy on loopback). Promote X-Forwarded-For
// and X-Forwarded-Proto into Connection.RemoteIpAddress / Request.Scheme so
// audit logs, rate limiters, and the login "System info" card show the real
// client — not 127.0.0.1. Restricted to loopback by default; if you ever
// terminate TLS off-host, add the proxy IP to KnownProxies.
app.UseForwardedHeaders();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();

// WebSocket support for the terminal proxy (/terminal/ws). Before routing so the
// Upgrade is handled; the endpoint still runs through auth/authorization below.
app.UseWebSockets();

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
