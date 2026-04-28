using NetFirewall.Services.Daemon;
using Spectre.Console;

namespace NetFirewall.Tui.Screens;

/// <summary>
/// Top-level menu. Pings the daemon on each render so the user sees the
/// connection state up front (and so a daemon-down condition is obvious
/// instead of failing on every submenu choice). Login state is shown on
/// the same status line — "logged in as X" or "not logged in". Submenus
/// that don't exist yet show as "[planned]".
/// </summary>
public sealed class MainMenu
{
    private readonly IDaemonClient _daemon;
    private readonly LoginScreen _login;
    private readonly NetworkInterfacesScreen _interfaces;
    private readonly RecoveryScreen _recovery;
    private readonly TuiSessionTokenProvider _tokenStore;
    private readonly UserSessionState _session;

    private const string LoginChoice = "Login";
    private const string LogoutChoice = "Logout";
    private const string NetworkChoice = "Network interfaces";
    private const string RecoveryChoice = "Recovery — reset admin / TOTP  [yellow](root only)[/]";
    private const string DaemonStatusChoice = "Daemon status";
    private const string QuitChoice = "Quit";

    public MainMenu(
        IDaemonClient daemon,
        LoginScreen login,
        NetworkInterfacesScreen interfaces,
        RecoveryScreen recovery,
        TuiSessionTokenProvider tokenStore,
        UserSessionState session)
    {
        _daemon = daemon;
        _login = login;
        _interfaces = interfaces;
        _recovery = recovery;
        _tokenStore = tokenStore;
        _session = session;
    }

    public async Task RunAsync()
    {
        while (true)
        {
            // ── Status line: daemon + auth ──
            var alive = await ProbeDaemonAsync();
            RenderStatusLine(alive);

            // ── Choices ──
            // Recovery is intentionally outside the IsLoggedIn gate: it's the
            // break-glass path for "I can't log in". Daemon enforces root-peer
            // for those endpoints, not session.
            var choices = new List<string>();
            if (_session.IsLoggedIn)
            {
                choices.Add(NetworkChoice);
                choices.Add(LogoutChoice);
            }
            else
            {
                choices.Add(LoginChoice);
            }
            choices.Add(RecoveryChoice);
            choices.Add(DaemonStatusChoice);
            choices.Add(QuitChoice);

            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("[bold]Main menu[/]")
                    .PageSize(10)
                    .HighlightStyle(new Style(foreground: Color.Aqua))
                    .AddChoices(choices));

            switch (choice)
            {
                case LoginChoice:
                    await _login.RunAsync();
                    AnsiConsole.Clear();
                    break;
                case LogoutChoice:
                    await DoLogoutAsync();
                    AnsiConsole.Clear();
                    break;
                case NetworkChoice:
                    await _interfaces.RunAsync();
                    AnsiConsole.Clear();
                    break;
                case RecoveryChoice:
                    await _recovery.RunAsync();
                    AnsiConsole.Clear();
                    break;
                case DaemonStatusChoice:
                    await ShowDaemonStatusAsync();
                    break;
                case QuitChoice:
                    AnsiConsole.MarkupLine("[dim]Bye.[/]");
                    return;
                default:
                    AnsiConsole.MarkupLine("[yellow]Not implemented yet — coming in v0.4.[/]");
                    AnsiConsole.MarkupLine("[dim]Press any key to return to the menu.[/]");
                    Console.ReadKey(intercept: true);
                    AnsiConsole.Clear();
                    break;
            }
        }
    }

    private async Task<bool> ProbeDaemonAsync()
    {
        // 2-second ceiling — we don't want the menu to hang if the socket is
        // gone. The IDaemonClient implementation already swallows transport
        // exceptions and returns false, so this is just defence-in-depth.
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        try { return await _daemon.IsAliveAsync(cts.Token); }
        catch { return false; }
    }

    private void RenderStatusLine(bool alive)
    {
        var color = alive ? "green" : "red";
        var label = alive ? "ONLINE" : "OFFLINE";
        AnsiConsole.MarkupLine($"Daemon: [{color}]{label}[/]   " + (alive
            ? "[dim]Talking to daemon over Unix socket.[/]"
            : "[dim]Daemon not reachable — start it or check appsettings.json.[/]"));

        if (_session.IsLoggedIn)
        {
            var name = _session.DisplayName ?? _session.Username!;
            AnsiConsole.MarkupLineInterpolated(
                $"User:   [aqua]{name}[/]   [dim]session expires {_session.ExpiresAt!.Value.LocalDateTime:t}[/]");
        }
        else
        {
            AnsiConsole.MarkupLine("User:   [dim]not logged in (anonymous — only Daemon Status is reachable)[/]");
        }
        AnsiConsole.WriteLine();
    }

    private async Task DoLogoutAsync()
    {
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Logging out...", async _ => await _daemon.LogoutAsync());

        // Whether the daemon call succeeded or not, dump the local token —
        // the user pressed logout, they want their state gone.
        _tokenStore.SetToken(null);
        _session.Clear();
    }

    private async Task ShowDaemonStatusAsync()
    {
        AnsiConsole.Clear();
        AnsiConsole.Write(new Rule("[aqua]Daemon status[/]").LeftJustified());

        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Probing daemon...", async _ =>
            {
                var alive = await ProbeDaemonAsync();
                var ruleset = alive ? await _daemon.GetCurrentRulesetAsync() : null;

                var table = new Table().Border(TableBorder.Rounded);
                table.AddColumn("Property");
                table.AddColumn("Value");
                table.AddRow("Reachable", alive ? "[green]yes[/]" : "[red]no[/]");
                table.AddRow("Current nft ruleset",
                    ruleset is null
                        ? "[dim](unavailable — login required)[/]"
                        : $"[dim]{ruleset.Length} bytes loaded[/]");

                AnsiConsole.Write(table);
            });

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[dim]Press any key to return to the menu.[/]");
        Console.ReadKey(intercept: true);
        AnsiConsole.Clear();
    }
}
