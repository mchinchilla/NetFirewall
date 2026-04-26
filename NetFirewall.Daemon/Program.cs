using System.Net.Sockets;
using Microsoft.AspNetCore.Authentication;
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

var builder = WebApplication.CreateBuilder(args);

// ----- Logging -----
builder.Host.UseSerilog((ctx, services, configuration) =>
    configuration
        .ReadFrom.Configuration(ctx.Configuration)
        .ReadFrom.Services(services));

builder.AddServiceDefaults();

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

builder.Services.AddKeyedSingleton<INetworkConfigService, DebianInterfacesConfigService>(NetworkConfigMethod.Interfaces);
builder.Services.AddKeyedSingleton<INetworkConfigService, NetplanConfigService>(NetworkConfigMethod.Netplan);
builder.Services.AddKeyedSingleton<INetworkConfigService, NetworkManagerConfigService>(NetworkConfigMethod.NetworkManager);
builder.Services.AddKeyedSingleton<INetworkConfigService, NoOpNetworkConfigService>(NetworkConfigMethod.Unknown);
builder.Services.AddSingleton<INetworkConfigResolver, NetworkConfigResolver>();
builder.Services.AddScoped<IStaticRouteApplicator, StaticRouteApplicator>();

// ----- Auth services (sessions read from same Postgres as Web) -----
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<ISessionService, SessionService>();
builder.Services.AddScoped<IAuthAuditService, AuthAuditService>();

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
app.UseAuthorization();

// Health probe — no auth, useful for AppHost / monitoring.
app.MapGet("/health", () => Results.Json(new { status = "ok", version = ThisVersion() }))
   .AllowAnonymous();

// Protected v1 endpoints.
app.MapNetworkEndpoints();
app.MapRouteEndpoints();

ApplySocketMode(daemonOpts);
Log.Information("NetFirewall daemon listening on Unix socket {Socket}", ResolveSocketPath(daemonOpts.SocketPath));

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
}

static string ThisVersion() =>
    typeof(Program).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";
