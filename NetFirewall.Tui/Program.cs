using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NetFirewall.Services.Daemon;
using NetFirewall.Tui;
using NetFirewall.Tui.Screens;
using Spectre.Console;

// ── Configuration ─────────────────────────────────────────────────────
//
// Resolve appsettings.json relative to the binary directory so the TUI
// works whether invoked from /opt/netfirewall/tui/ (production) or
// `dotnet run` (dev). Env vars override JSON for ops who'd rather set
// `Daemon__SocketPath` than edit a file.
var binDir = AppContext.BaseDirectory;
var configuration = new ConfigurationBuilder()
    .SetBasePath(binDir)
    .AddJsonFile("appsettings.json", optional: true)
    .AddEnvironmentVariables()
    .Build();

// ── DI container ──────────────────────────────────────────────────────
//
// Same patterns as the Web: bind DaemonClientOptions, register the daemon
// transport, plug in a TUI-specific session token provider. The provider
// starts as Null (no token = anonymous = read-only paths only). When/if
// the user logs in via the TUI, we swap in a token-holding implementation.
var services = new ServiceCollection();

services.Configure<DaemonClientOptions>(configuration.GetSection(DaemonClientOptions.SectionName));
services.AddLogging(builder =>
{
    builder.AddConfiguration(configuration.GetSection("Logging"));
    // No console sink by default — the TUI owns the screen, log lines would
    // tear the chrome. Re-enable for debugging with `Logging__LogLevel__Default=Debug`.
    builder.SetMinimumLevel(LogLevel.Warning);
});

// The token provider is registered TWICE under different service types so
// other components can take TuiSessionTokenProvider concrete (to call SetToken)
// while everything else takes the IDaemonSessionTokenProvider abstraction.
services.AddSingleton<TuiSessionTokenProvider>();
services.AddSingleton<IDaemonSessionTokenProvider>(sp => sp.GetRequiredService<TuiSessionTokenProvider>());
services.AddSingleton<IDaemonClient, DaemonClient>();
services.AddSingleton<UserSessionState>();
services.AddSingleton<LoginScreen>();
services.AddSingleton<NetworkInterfacesScreen>();
services.AddSingleton<MainMenu>();

await using var sp = services.BuildServiceProvider();

// ── Banner + boot ─────────────────────────────────────────────────────
AnsiConsole.Write(
    new FigletText("NetFirewall TUI")
        .Centered()
        .Color(Color.Aqua));

AnsiConsole.MarkupLine("[dim]Local console for the NetFirewall daemon. Talks to the same Unix socket the Web uses.[/]");
AnsiConsole.WriteLine();

await sp.GetRequiredService<MainMenu>().RunAsync();
