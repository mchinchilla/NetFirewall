using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Daemon;
using Spectre.Console;

namespace NetFirewall.Tui.Screens;

/// <summary>
/// Single-step login flow for the TUI. Prompts for username, password (masked),
/// and TOTP/recovery code in one screen — TTYs can ask for everything at once,
/// no need for the Web's multi-page <c>/login</c> → <c>/login/totp</c> dance.
/// On success, stores the issued token in <see cref="TuiSessionTokenProvider"/>
/// so subsequent daemon calls authenticate as the user.
/// </summary>
public sealed class LoginScreen
{
    private readonly IDaemonClient _daemon;
    private readonly TuiSessionTokenProvider _tokenStore;
    private readonly UserSessionState _session;

    public LoginScreen(IDaemonClient daemon, TuiSessionTokenProvider tokenStore, UserSessionState session)
    {
        _daemon = daemon;
        _tokenStore = tokenStore;
        _session = session;
    }

    /// <summary>Returns true if the user successfully logged in (or was already in).</summary>
    public async Task<bool> RunAsync(CancellationToken ct = default)
    {
        AnsiConsole.Clear();
        AnsiConsole.Write(new Rule("[aqua]Login[/]").LeftJustified());
        AnsiConsole.MarkupLine("[dim]Authenticate against the same user store the Web uses.[/]");
        AnsiConsole.MarkupLine("[dim]Press Ctrl+C to cancel.[/]");
        AnsiConsole.WriteLine();

        var username = AnsiConsole.Prompt(
            new TextPrompt<string>("Username:")
                .PromptStyle("aqua")
                .ValidationErrorMessage("[red]Username is required.[/]")
                .Validate(s => !string.IsNullOrWhiteSpace(s)
                    ? ValidationResult.Success()
                    : ValidationResult.Error("Username cannot be empty")));

        var password = AnsiConsole.Prompt(
            new TextPrompt<string>("Password:")
                .PromptStyle("aqua")
                .Secret() // masks input — Spectre handles the * rendering
                .ValidationErrorMessage("[red]Password is required.[/]")
                .Validate(s => !string.IsNullOrWhiteSpace(s)
                    ? ValidationResult.Success()
                    : ValidationResult.Error("Password cannot be empty")));

        var useRecovery = AnsiConsole.Confirm(
            "Use a [yellow]recovery code[/] instead of TOTP?", defaultValue: false);

        var codeLabel = useRecovery ? "Recovery code:" : "TOTP code (6 digits):";
        var code = AnsiConsole.Prompt(
            new TextPrompt<string>(codeLabel)
                .PromptStyle("aqua")
                .ValidationErrorMessage("[red]Code is required.[/]")
                .Validate(s => !string.IsNullOrWhiteSpace(s)
                    ? ValidationResult.Success()
                    : ValidationResult.Error("Code cannot be empty")));

        var request = new TuiLoginRequest(username.Trim(), password, code.Trim(), useRecovery);

        ServiceResponse<TuiLoginResult>? envelope = null;
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Authenticating...", async _ =>
            {
                envelope = await _daemon.LoginAsync(request, ct);
            });

        if (envelope is null || !envelope.Success || envelope.Data is null)
        {
            // Failure path: show the daemon's message verbatim. Includes
            // lockout / disabled-account / bad-code copy so the user gets
            // the same actionable feedback the Web would show.
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLineInterpolated($"[red]Login failed:[/] {envelope?.Message ?? "Unknown error"}");
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("[dim]Press any key to return.[/]");
            Console.ReadKey(intercept: true);
            return false;
        }

        // Success — stash the token + cache the user identity for the menu line.
        _tokenStore.SetToken(envelope.Data.Token);
        _session.Set(envelope.Data.Username, envelope.Data.DisplayName, envelope.Data.ExpiresAt);

        AnsiConsole.WriteLine();
        var who = envelope.Data.DisplayName ?? envelope.Data.Username;
        var when = envelope.Data.ExpiresAt.LocalDateTime;
        AnsiConsole.MarkupLineInterpolated($"[green]Welcome, {who}.[/] Session valid until [yellow]{when:t}[/].");
        AnsiConsole.MarkupLine("[dim]Press any key to continue.[/]");
        Console.ReadKey(intercept: true);
        return true;
    }
}

/// <summary>
/// In-memory record of who's logged in. Separate from
/// <see cref="TuiSessionTokenProvider"/> (which holds only the opaque token)
/// so the menu can show "Logged in as Alice" without leaking the token to
/// every screen that wants the username.
/// </summary>
public sealed class UserSessionState
{
    public string? Username { get; private set; }
    public string? DisplayName { get; private set; }
    public DateTimeOffset? ExpiresAt { get; private set; }

    public bool IsLoggedIn => Username is not null;

    public void Set(string username, string? displayName, DateTimeOffset expiresAt)
    {
        Username = username;
        DisplayName = displayName;
        ExpiresAt = expiresAt;
    }

    public void Clear()
    {
        Username = null;
        DisplayName = null;
        ExpiresAt = null;
    }
}
