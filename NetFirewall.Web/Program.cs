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

// ----- Network config writers + resolver -----
builder.Services.AddKeyedSingleton<INetworkConfigService, DebianInterfacesConfigService>(NetworkConfigMethod.Interfaces);
builder.Services.AddKeyedSingleton<INetworkConfigService, NetplanConfigService>(NetworkConfigMethod.Netplan);
builder.Services.AddKeyedSingleton<INetworkConfigService, NetworkManagerConfigService>(NetworkConfigMethod.NetworkManager);
builder.Services.AddKeyedSingleton<INetworkConfigService, NoOpNetworkConfigService>(NetworkConfigMethod.Unknown);
builder.Services.AddSingleton<INetworkConfigResolver, NetworkConfigResolver>();
builder.Services.AddScoped<IStaticRouteApplicator, StaticRouteApplicator>();

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

// Bootstrap: holds the one-time admin-creation token; issuer is a hosted service.
builder.Services.AddSingleton<IBootstrapTokenStore, BootstrapTokenStore>();
builder.Services.AddHostedService<BootstrapTokenIssuer>();

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
