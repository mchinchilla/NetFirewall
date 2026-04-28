using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Daemon;
using Spectre.Console;

namespace NetFirewall.Tui.Screens;

/// <summary>
/// Break-glass screen for the "I locked myself out" scenario. Reachable from
/// the top-level menu WITHOUT logging in — recovery is exactly the case where
/// you can't. Auth on the daemon side is purely peer-cred root, so this only
/// works when the TUI was launched as root (typically via <c>sudo netfirewall-tui</c>
/// from a physical console / serial / KVM session).
///
/// <para>Two actions today: reset a user's password, or disable TOTP for a user
/// (so they can re-enroll on next Web login). Both also clear lockout state
/// so the user can immediately log in afterwards.</para>
/// </summary>
public sealed class RecoveryScreen
{
    private readonly IDaemonClient _daemon;

    private const string ResetPasswordAction = "Reset password";
    private const string DisableTotpAction = "Disable TOTP (force re-enroll)";
    private const string CancelAction = "← Cancel";

    public RecoveryScreen(IDaemonClient daemon)
    {
        _daemon = daemon;
    }

    public async Task RunAsync(CancellationToken ct = default)
    {
        AnsiConsole.Clear();
        AnsiConsole.Write(new Rule("[red]Recovery — break glass[/]").LeftJustified());
        AnsiConsole.MarkupLine("[yellow]These actions bypass the normal login flow.[/] [dim]They require running the TUI as root (sudo).[/]");
        AnsiConsole.WriteLine();

        var users = await FetchUsersAsync(ct);
        if (users is null) return;

        if (users.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No users in the database.[/] [dim]Run the setup wizard via the Web first.[/]");
            AnsiConsole.MarkupLine("[dim]Press any key to return.[/]");
            Console.ReadKey(intercept: true);
            return;
        }

        RenderUsersTable(users);

        var pickedLabel = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold]Pick a user[/]")
                .HighlightStyle(new Style(foreground: Color.Aqua))
                .AddChoices(users.Select(BuildUserChoiceLabel).Append(CancelAction)));

        if (pickedLabel == CancelAction) return;

        var picked = users.First(u => BuildUserChoiceLabel(u) == pickedLabel);

        var action = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title($"[bold]Action for[/] [aqua]{picked.Username}[/]")
                .HighlightStyle(new Style(foreground: Color.Aqua))
                .AddChoices(ResetPasswordAction, DisableTotpAction, CancelAction));

        switch (action)
        {
            case ResetPasswordAction:
                await DoResetPasswordAsync(picked, ct);
                break;
            case DisableTotpAction:
                await DoDisableTotpAsync(picked, ct);
                break;
            default:
                return;
        }
    }

    // ── Fetch + render ─────────────────────────────────────────────────

    private async Task<IReadOnlyList<RecoveryUserSummary>?> FetchUsersAsync(CancellationToken ct)
    {
        ServiceResponse<IReadOnlyList<RecoveryUserSummary>>? resp = null;
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Loading users...", async _ =>
            {
                resp = await _daemon.ListUsersForRecoveryAsync(ct);
            });

        if (resp is null || !resp.Success)
        {
            ShowDaemonError(resp?.Message
                ?? "Failed to load users. Recovery requires running the TUI as root (sudo).");
            return null;
        }
        return resp.Data ?? Array.Empty<RecoveryUserSummary>();
    }

    private static void RenderUsersTable(IReadOnlyList<RecoveryUserSummary> users)
    {
        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("Username");
        table.AddColumn("Display name");
        table.AddColumn("Role");
        table.AddColumn("Active");
        table.AddColumn("Locked");
        table.AddColumn("TOTP");

        foreach (var u in users)
        {
            table.AddRow(
                u.Username,
                u.DisplayName ?? "[dim]—[/]",
                u.Role,
                u.IsActive ? "[green]yes[/]" : "[red]no[/]",
                u.IsLocked ? "[red]yes[/]" : "[green]no[/]",
                u.HasTotp ? "[green]yes[/]" : "[yellow]no[/]");
        }

        AnsiConsole.Write(table);
        AnsiConsole.WriteLine();
    }

    /// <summary>
    /// Render a one-line picker label. Includes the lock + TOTP markers so the
    /// operator picks the right account at a glance.
    /// </summary>
    internal static string BuildUserChoiceLabel(RecoveryUserSummary u)
    {
        var marks = new List<string>();
        if (u.IsLocked) marks.Add("locked");
        if (!u.IsActive) marks.Add("inactive");
        if (!u.HasTotp) marks.Add("no-totp");
        var suffix = marks.Count > 0 ? $"  [dim]({string.Join(", ", marks)})[/]" : string.Empty;
        return $"{u.Username}  [dim]· {u.Role}[/]{suffix}";
    }

    // ── Reset password ─────────────────────────────────────────────────

    private async Task DoResetPasswordAsync(RecoveryUserSummary user, CancellationToken ct)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLineInterpolated($"Resetting password for [aqua]{user.Username}[/].");
        AnsiConsole.MarkupLine("[dim]Password must be at least 8 characters. Won't be echoed.[/]");

        string newPassword;
        while (true)
        {
            var first = AnsiConsole.Prompt(
                new TextPrompt<string>("New password:")
                    .PromptStyle("aqua")
                    .Secret()
                    .Validate(s => !string.IsNullOrEmpty(s) && s.Length >= 8
                        ? ValidationResult.Success()
                        : ValidationResult.Error("At least 8 characters")));
            var confirm = AnsiConsole.Prompt(
                new TextPrompt<string>("Confirm:")
                    .PromptStyle("aqua")
                    .Secret());
            if (first == confirm)
            {
                newPassword = first;
                break;
            }
            AnsiConsole.MarkupLine("[red]Passwords don't match. Try again.[/]");
        }

        if (!AnsiConsole.Confirm(
                $"Reset password for [aqua]{user.Username}[/] and clear lockout?",
                defaultValue: false))
        {
            return;
        }

        ServiceResponse<RecoveryActionResult>? resp = null;
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Applying...", async _ =>
            {
                resp = await _daemon.RecoveryResetPasswordAsync(user.Username, newPassword, ct);
            });

        if (resp is null || !resp.Success)
        {
            ShowDaemonError(resp?.Message ?? "Reset failed.");
            return;
        }

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLineInterpolated(
            $"[green]Password reset for {user.Username}.[/]  Lockout cleared. The user can log in immediately.");
        AnsiConsole.MarkupLine("[dim]Press any key to return.[/]");
        Console.ReadKey(intercept: true);
    }

    // ── Disable TOTP ───────────────────────────────────────────────────

    private async Task DoDisableTotpAsync(RecoveryUserSummary user, CancellationToken ct)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLineInterpolated($"This will [red]wipe the TOTP secret[/] for [aqua]{user.Username}[/].");
        AnsiConsole.MarkupLine("[dim]The user must enroll a new TOTP device on their next Web login.[/]");
        AnsiConsole.MarkupLine("[dim]Lockout will also be cleared so the next login isn't blocked.[/]");
        AnsiConsole.WriteLine();

        if (!AnsiConsole.Confirm(
                $"Disable TOTP for [aqua]{user.Username}[/]?",
                defaultValue: false))
        {
            return;
        }

        ServiceResponse<RecoveryActionResult>? resp = null;
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Applying...", async _ =>
            {
                resp = await _daemon.RecoveryDisableTotpAsync(user.Username, ct);
            });

        if (resp is null || !resp.Success)
        {
            ShowDaemonError(resp?.Message ?? "Disable failed.");
            return;
        }

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLineInterpolated(
            $"[green]TOTP disabled for {user.Username}.[/]  Lockout cleared. They will be prompted to re-enroll on next Web login.");
        AnsiConsole.MarkupLine("[dim]Press any key to return.[/]");
        Console.ReadKey(intercept: true);
    }

    private static void ShowDaemonError(string message)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLineInterpolated($"[red]Error:[/] {message}");
        AnsiConsole.MarkupLine("[dim]Press any key to return.[/]");
        Console.ReadKey(intercept: true);
    }
}
