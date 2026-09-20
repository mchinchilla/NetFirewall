using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NetFirewall.Services.Daemon;
using NetFirewall.Tui;
using NetFirewall.Tui.Screens;
using Spectre.Console;

// ── Help ──────────────────────────────────────────────────────────────
//
// Handled before anything else: no config, no DI, no socket. The bash
// completion shipped in deploy/completion/ already advertises these flags.
if (args.Contains("--help") || args.Contains("-h"))
{
    Console.WriteLine("""
        netfirewall-tui — console UI for the NetFirewall daemon

        USAGE
          sudo netfirewall-tui

        An interactive text UI that talks to the local daemon over its Unix
        socket. It takes no subcommands: everything is driven from the menu.
        Intended for the two cases where the Web UI cannot help you:

          • Configuring the first network interface on a fresh host, before
            the Web is reachable.
          • Recovering a locked-out admin or a lost TOTP device, when the Web
            login flow is blocked.

        MENU
          Network interfaces   List, edit (IP / mask / gateway / MAC / MTU) and
                               add interfaces from physically-detected NICs,
                               then apply them through the daemon.
          Recovery             Reset a password, disable TOTP and clear lockout.
                               Needs no login — the daemon authorises it by the
                               connecting peer being root.
          Daemon status        Read-only health ping and the live nft ruleset.

        OPTIONS
          --help, -h           Show this help.

        AUTHENTICATION
          The daemon gates its socket by peer credentials, so run this as root
          (sudo) or as a member of the netfirewall group. Logging in asks for
          username, password and TOTP in one screen; a TUI session is elevated
          from the start, because you already proved TOTP at a physical console.

        ENVIRONMENT
          Daemon__SocketPath   Override the daemon socket path.
                               Default: /run/netfirewall/control.sock

        EXIT STATUS
          0   Clean exit (Quit from the menu).
          1   The TUI could not start — usually an unreadable appsettings.json
              or a daemon socket it cannot open.

        SEE ALSO
          netfirewall-tui(1), netfirewall-doctor --help
        """);
    return;
}

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
services.AddSingleton<RecoveryScreen>();
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
