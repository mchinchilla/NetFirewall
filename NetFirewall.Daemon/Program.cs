using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using NetFirewall.Daemon;
using NetFirewall.Daemon.Auth;
using NetFirewall.Daemon.Endpoints;
using NetFirewall.Models.System;
using NetFirewall.Services.Auth;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Services.Processes;
using Npgsql;
using RepoDb;
using Serilog;

[assembly: SupportedOSPlatform("linux")]

var builder = WebApplication.CreateBuilder(args);

// systemd integration: sends sd_notify READY=1 once the host is started,
// satisfying the Type=notify unit. No-op on non-systemd hosts.
builder.Host.UseSystemd();

// ----- Logging -----
builder.Host.UseSerilog((ctx, services, configuration) =>
    configuration
        .ReadFrom.Configuration(ctx.Configuration)
        .ReadFrom.Services(services));

builder.AddServiceDefaults();

// DataProtection keys persist to disk so the daemon's antiforgery / session
// crypto survives restarts. The daemon doesn't directly issue cookies but
// the framework still spins up a key ring at startup; without this it warns
// loudly about ephemeral keys every time.
{
    var keysDir = builder.Configuration["DataProtectionKeysDir"]
                  ?? (builder.Environment.IsProduction()
                      ? "/var/lib/netfirewall/daemon/keys"
                      : Path.Combine(builder.Environment.ContentRootPath, ".dp-keys"));
    Directory.CreateDirectory(keysDir);
    builder.Services.AddDataProtection()
        .PersistKeysToFileSystem(new DirectoryInfo(keysDir))
        .SetApplicationName("NetFirewall.Daemon");
}

// ----- HTTP JSON options -----
// System.Text.Json can't serialize IPAddress out of the box (emits {}). Any
// endpoint returning a DTO with an IPAddress field (e.g. /v1/system/top-talkers)
// would otherwise round-trip as null and the dashboard panel would render empty.
builder.Services.ConfigureHttpJsonOptions(o =>
{
    o.SerializerOptions.Converters.Add(new NetFirewall.Services.Json.IPAddressJsonConverter());
});

// ----- Daemon options -----
builder.Services.Configure<DaemonOptions>(builder.Configuration.GetSection(DaemonOptions.SectionName));
var daemonOpts = builder.Configuration.GetSection(DaemonOptions.SectionName).Get<DaemonOptions>() ?? new DaemonOptions();

// ----- Kestrel: bind ONLY a Unix socket -----
builder.WebHost.ConfigureKestrel((ctx, k) =>
{
    var socketPath = ResolveSocketPath(daemonOpts.SocketPath);
    EnsureSocketDir(socketPath);
    if (File.Exists(socketPath)) File.Delete(socketPath);

    k.ListenUnixSocket(socketPath, lo => lo.Protocols = HttpProtocols.Http1);
    k.AddServerHeader = false;
});

// ----- Database (shared with Web) -----
GlobalConfiguration.Setup().UsePostgreSql();
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection")
                       ?? throw new InvalidOperationException("ConnectionStrings:DefaultConnection is required.");
var dataSourceBuilder = new NpgsqlDataSourceBuilder(connectionString);
builder.Services.AddSingleton(dataSourceBuilder.Build());

// ----- Domain services (mirror of Web's registrations) -----
builder.Services.AddSingleton<IProcessRunner, ProcessRunner>();
builder.Services.AddSingleton<ILinuxDistroService, LinuxDistroService>();
builder.Services.AddScoped<IFirewallService, FirewallService>();
builder.Services.AddScoped<INftApplyService, NftApplyService>();
builder.Services.AddScoped<ITcApplyService, TcApplyService>();
builder.Services.AddScoped<NetFirewall.Services.Network.IDnsForwarderService,
                           NetFirewall.Services.Network.UnboundForwarderService>();
builder.Services.AddScoped<IScheduleService, ScheduleService>();
builder.Services.Configure<NftApplyOptions>(builder.Configuration.GetSection("Nft"));
builder.Services.Configure<TcApplyOptions>(builder.Configuration.GetSection("Tc"));

// Network objects + resolver — needed by FirewallService for nft generation
// (resolves named source/destination references → flat CIDRs).
builder.Services.AddScoped<NetFirewall.Services.Network.INetworkObjectService,
                           NetFirewall.Services.Network.NetworkObjectService>();
builder.Services.AddScoped<NetFirewall.Services.Network.INetworkObjectResolver,
                           NetFirewall.Services.Network.NetworkObjectResolver>();

// Network services + resolver — same idea but L4 (port/protocol catalog).
builder.Services.AddScoped<NetFirewall.Services.Network.INetworkServiceService,
                           NetFirewall.Services.Network.NetworkServiceService>();
builder.Services.AddScoped<NetFirewall.Services.Network.INetworkServiceResolver,
                           NetFirewall.Services.Network.NetworkServiceResolver>();

builder.Services.AddKeyedSingleton<INetworkConfigService, DebianInterfacesConfigService>(NetworkConfigMethod.Interfaces);
builder.Services.AddKeyedSingleton<INetworkConfigService, NetplanConfigService>(NetworkConfigMethod.Netplan);
builder.Services.AddKeyedSingleton<INetworkConfigService, NetworkManagerConfigService>(NetworkConfigMethod.NetworkManager);
builder.Services.AddKeyedSingleton<INetworkConfigService, NoOpNetworkConfigService>(NetworkConfigMethod.Unknown);
builder.Services.AddSingleton<INetworkConfigResolver, NetworkConfigResolver>();
builder.Services.AddScoped<IStaticRouteApplicator, StaticRouteApplicator>();

// ----- Settings — same singleton service the Web uses, lets the collector
//        and audit pruner read operator-tunable retention values. -----
builder.Services.AddSingleton<NetFirewall.Services.Settings.IAppSettingsService,
                              NetFirewall.Services.Settings.AppSettingsService>();

// ----- Monitoring (collector runs HERE, not in Web — daemon is long-lived
//        and stays running across Web restarts so we don't lose samples). -----
builder.Services.AddSingleton<NetFirewall.Services.Monitoring.ISystemMonitorService,
                              NetFirewall.Services.Monitoring.SystemMonitorService>();
builder.Services.AddSingleton<NetFirewall.Services.Monitoring.ISystemServiceHealthService,
                              NetFirewall.Services.Monitoring.SystemServiceHealthService>();
builder.Services.AddScoped<NetFirewall.Services.Monitoring.ITopTalkersService,
                           NetFirewall.Services.Monitoring.TopTalkersService>();
builder.Services.Configure<NetFirewall.Services.Monitoring.ConntrackSamplerOptions>(
    builder.Configuration.GetSection(NetFirewall.Services.Monitoring.ConntrackSamplerOptions.SectionName));
builder.Services.AddSingleton<NetFirewall.Services.Monitoring.ILocalAddressProvider,
                              NetFirewall.Services.Monitoring.LocalAddressProvider>();

// IP→ASN enrichment: one IpAsnResolver instance is BOTH the IIpAsnResolver the
// sampler enqueues into AND the BackgroundService that drains the queue. Register
// the concrete singleton once, then forward both roles to it. AddHttpClient gives
// it a typed HttpClient (ServiceDefaults adds the resilience handler by default).
builder.Services.Configure<NetFirewall.Services.Monitoring.IpAsnResolverOptions>(
    builder.Configuration.GetSection(NetFirewall.Services.Monitoring.IpAsnResolverOptions.SectionName));
builder.Services.AddHttpClient(NetFirewall.Services.Monitoring.IpAsnResolver.HttpClientName);
builder.Services.AddSingleton<NetFirewall.Services.Monitoring.IpAsnResolver>();
builder.Services.AddSingleton<NetFirewall.Services.Monitoring.IIpAsnResolver>(
    sp => sp.GetRequiredService<NetFirewall.Services.Monitoring.IpAsnResolver>());
builder.Services.AddHostedService(
    sp => sp.GetRequiredService<NetFirewall.Services.Monitoring.IpAsnResolver>());

builder.Services.AddHostedService<NetFirewall.Services.Monitoring.ConntrackSamplerService>();

// WAN health monitor — absorbs the standalone NetFirewall.WanMonitor process.
// Probes each WAN, persists state to wan_health_state, swaps the default
// route in the main table when priority winner changes.
builder.Services.AddScoped<NetFirewall.Services.WanMonitor.IWanHealthService,
                           NetFirewall.Services.WanMonitor.WanHealthService>();
builder.Services.Configure<NetFirewall.Services.WanMonitor.WanHealthMonitorOptions>(
    builder.Configuration.GetSection(NetFirewall.Services.WanMonitor.WanHealthMonitorOptions.SectionName));
builder.Services.AddHostedService<NetFirewall.Services.WanMonitor.WanHealthMonitorService>();
builder.Services.AddScoped<NetFirewall.Services.Monitoring.IWanReachabilityService,
                           NetFirewall.Services.Monitoring.WanReachabilityService>();
builder.Services.AddScoped<NetFirewall.Services.Firewall.IApplyHistoryService,
                           NetFirewall.Services.Firewall.ApplyHistoryService>();
builder.Services.AddScoped<NetFirewall.Services.Firewall.IPolicyRoutingService,
                           NetFirewall.Services.Firewall.PolicyRoutingService>();
builder.Services.AddScoped<NetFirewall.Services.Firewall.IPolicyRoutingApplyService,
                           NetFirewall.Services.Firewall.PolicyRoutingApplyService>();
builder.Services.AddScoped<NetFirewall.Services.Monitoring.IMetricsQueryService,
                           NetFirewall.Services.Monitoring.MetricsQueryService>();
builder.Services.Configure<NetFirewall.Services.Monitoring.MetricsCollectorOptions>(
    builder.Configuration.GetSection("Metrics"));
builder.Services.AddHostedService<NetFirewall.Services.Monitoring.MetricsCollectorService>();
builder.Services.AddHostedService<NetFirewall.Services.Firewall.AuditPrunerService>();
// Schedule watcher — re-applies nft when any time-based filter rule
// transitions active/inactive. Ticks every 60s, no-op when nothing changed.
builder.Services.AddHostedService<NetFirewall.Services.Firewall.ScheduleWatcherService>();

// ----- Auth services (sessions read from same Postgres as Web) -----
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<ISessionService, SessionService>();
builder.Services.AddScoped<IAuthAuditService, AuthAuditService>();

// Hasher / TOTP / recovery codes — needed by /v1/auth/login (TUI). The Web
// owns the same services in its own DI; the daemon registers them too because
// it now hosts a full login flow for headless clients.
builder.Services.AddSingleton<IPasswordHasher, Argon2PasswordHasher>();
builder.Services.AddSingleton<ITotpService, TotpService>();
builder.Services.AddScoped<IUserTotpService, UserTotpService>();
builder.Services.AddScoped<IRecoveryCodeService, RecoveryCodeService>();

// TOTP cipher — the master key now lives HERE, not in the Web. The Web
// proxies encrypt/decrypt over the Unix socket via /v1/crypto/*. Singleton
// because the AES-256-GCM key never changes during process lifetime.
builder.Services.AddSingleton<ITotpSecretCipher, AesGcmTotpSecretCipher>();

// WireGuard — daemon owns key generation + apply (needs CAP_NET_ADMIN to
// bring the wg interface up). Web reads/writes the catalog over the same
// IWireGuardService and posts to /v1/wireguard/* for privileged ops.
builder.Services.AddScoped<NetFirewall.Services.Vpn.IWireGuardService,
                           NetFirewall.Services.Vpn.WireGuardService>();
builder.Services.AddSingleton<NetFirewall.Services.Vpn.IWireGuardConfigService,
                              NetFirewall.Services.Vpn.WireGuardConfigService>();
builder.Services.AddSingleton<NetFirewall.Services.Vpn.IWireGuardApplyService,
                              NetFirewall.Services.Vpn.WireGuardApplyService>();
builder.Services.AddScoped<NetFirewall.Services.Vpn.IWireGuardImporter,
                           NetFirewall.Services.Vpn.WireGuardImporter>();
builder.Services.Configure<NetFirewall.Services.Vpn.WireGuardApplyOptions>(
    builder.Configuration.GetSection("WireGuard"));

// ----- Authentication: validate X-NetFw-Session header -----
builder.Services
    .AddAuthentication(DaemonSessionAuthHandler.SchemeName)
    .AddScheme<DaemonSessionOptions, DaemonSessionAuthHandler>(
        DaemonSessionAuthHandler.SchemeName,
        opts => opts.HeaderName = daemonOpts.SessionHeader);
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseSerilogRequestLogging();

// First gate: peer UID. Defense-in-depth on top of FS perms.
app.UseMiddleware<PeerCredentialMiddleware>();

app.UseRouting();
app.UseAuthentication();
// Root-peer bypass: if the Unix-socket peer is uid 0 and didn't send a
// session header, treat the request as a system principal with elevated
// privileges. Lets netfirewall-bootstrap.service apply config at boot
// without needing a stored token. MUST run between UseAuthentication and
// UseAuthorization so the latter sees the synthetic principal.
app.UseMiddleware<NetFirewall.Daemon.Auth.RootPeerBypassMiddleware>();
app.UseAuthorization();

// Health probe — no auth, useful for AppHost / monitoring.
app.MapGet("/health", () => Results.Json(new { status = "ok", version = ThisVersion() }))
   .AllowAnonymous();

// Auth endpoints (/v1/auth/login, /v1/auth/logout) — login is anonymous,
// logout requires the session header.
app.MapAuthEndpoints();

// Recovery endpoints (/v1/auth/recovery/*) — root-peer-only, no session.
// Used by the TUI when the operator can't log in normally (lost TOTP, etc.).
app.MapRecoveryEndpoints();

// Protected v1 endpoints.
app.MapNetworkEndpoints();
app.MapRouteEndpoints();
app.MapFirewallEndpoints();
app.MapCryptoEndpoints();
app.MapSystemEndpoints();
app.MapWireGuardEndpoints();
app.MapDnsEndpoints();

// Kestrel only creates the Unix socket once the host has started, so chmod
// must run from the ApplicationStarted callback. Running it inline before
// app.Run() silently no-ops (File.Exists is false) and the socket stays at
// the umask default — blocking the Web from connecting.
app.Lifetime.ApplicationStarted.Register(() =>
{
    ApplySocketMode(daemonOpts);
    Log.Information("NetFirewall daemon listening on Unix socket {Socket}", ResolveSocketPath(daemonOpts.SocketPath));
});

app.Run();

// =====================================================================

static string ResolveSocketPath(string raw) =>
    Path.IsPathRooted(raw) ? raw : Path.GetFullPath(raw, Directory.GetCurrentDirectory());

static void EnsureSocketDir(string socketPath)
{
    var dir = Path.GetDirectoryName(socketPath);
    if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        Directory.CreateDirectory(dir);
}

static void ApplySocketMode(DaemonOptions opts)
{
    if (!OperatingSystem.IsLinux() && !OperatingSystem.IsMacOS()) return;
    var path = ResolveSocketPath(opts.SocketPath);
    if (!File.Exists(path)) return;

    try
    {
        // Convert "0660" → UnixFileMode flags.
        var mode = Convert.ToInt32(opts.SocketMode, 8);
        UnixFileMode flags = 0;
        if ((mode & 0x100) != 0) flags |= UnixFileMode.UserRead;
        if ((mode & 0x080) != 0) flags |= UnixFileMode.UserWrite;
        if ((mode & 0x040) != 0) flags |= UnixFileMode.UserExecute;
        if ((mode & 0x020) != 0) flags |= UnixFileMode.GroupRead;
        if ((mode & 0x010) != 0) flags |= UnixFileMode.GroupWrite;
        if ((mode & 0x008) != 0) flags |= UnixFileMode.GroupExecute;
        if ((mode & 0x004) != 0) flags |= UnixFileMode.OtherRead;
        if ((mode & 0x002) != 0) flags |= UnixFileMode.OtherWrite;
        if ((mode & 0x001) != 0) flags |= UnixFileMode.OtherExecute;
        File.SetUnixFileMode(path, flags);
    }
    catch (Exception ex)
    {
        Log.Warning(ex, "Failed to apply socket mode {Mode} to {Path}", opts.SocketMode, path);
    }

    // chown the socket to the configured group. Without this the group owner
    // stays root:root and the chmod g+rw above is useless to the Web user.
    // Only meaningful on Linux; .NET doesn't expose chown so we P/Invoke.
    if (OperatingSystem.IsLinux() && !string.IsNullOrWhiteSpace(opts.SocketGroup))
    {
        var gid = NativeMethods.GetGroupId(opts.SocketGroup);
        if (gid is null)
        {
            Log.Warning("Socket group {Group} not found on this host; leaving socket as root:root", opts.SocketGroup);
        }
        else if (NativeMethods.Chown(path, uint.MaxValue, gid.Value) != 0)
        {
            var err = Marshal.GetLastPInvokeError();
            Log.Warning("chown({Path}, -1, {Gid}) failed: errno={Errno}", path, gid.Value, err);
        }
        else
        {
            Log.Information("Socket group set to {Group} (gid {Gid})", opts.SocketGroup, gid.Value);
        }
    }
}

static string ThisVersion() =>
    typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
