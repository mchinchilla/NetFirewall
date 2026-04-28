using System.Net;
using NetFirewall.Models;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.System;
using NetFirewall.Services.Daemon;
using Spectre.Console;

namespace NetFirewall.Tui.Screens;

/// <summary>
/// The TUI's killer screen: list configured interfaces, edit IP/mask/gateway/MAC,
/// add new ones from physically-detected NICs, apply via daemon. Designed for
/// the "fresh Debian install, no network yet" scenario — the operator can give
/// the box an IP without ever leaving the console.
///
/// All daemon writes (create / update / apply) require an elevated session.
/// TUI sessions are born elevated (login already proved TOTP), so the screen
/// never re-prompts. If the daemon ever returns 403 elevation_required, the
/// envelope's <c>Message</c> is shown verbatim and the user is sent back to
/// the menu.
/// </summary>
public sealed class NetworkInterfacesScreen
{
    private readonly IDaemonClient _daemon;

    public NetworkInterfacesScreen(IDaemonClient daemon)
    {
        _daemon = daemon;
    }

    public async Task RunAsync(CancellationToken ct = default)
    {
        while (true)
        {
            AnsiConsole.Clear();
            AnsiConsole.Write(new Rule("[aqua]Network interfaces[/]").LeftJustified());

            var listResp = await FetchListAsync(ct);
            if (listResp is null) return; // user cancelled / unrecoverable

            RenderInterfacesTable(listResp);

            var choice = AnsiConsole.Prompt(
                new SelectionPrompt<string>()
                    .Title("[bold]Action[/]")
                    .HighlightStyle(new Style(foreground: Color.Aqua))
                    .AddChoices(BuildActionChoices(listResp)));

            if (choice == BackChoice) return;

            if (choice == AddChoice)
            {
                await AddInterfaceFlowAsync(ct);
                continue;
            }

            if (choice.StartsWith(EditPrefix))
            {
                var name = choice[EditPrefix.Length..];
                var iface = listResp.FirstOrDefault(i => i.Name == name);
                if (iface is not null) await EditInterfaceFlowAsync(iface, ct);
                continue;
            }

            if (choice.StartsWith(ApplyPrefix))
            {
                var name = choice[ApplyPrefix.Length..];
                var iface = listResp.FirstOrDefault(i => i.Name == name);
                if (iface is not null) await ApplyInterfaceAsync(iface, ct);
                continue;
            }
        }
    }

    // ── Fetch + render ─────────────────────────────────────────────────

    private async Task<IReadOnlyList<FwInterface>?> FetchListAsync(CancellationToken ct)
    {
        ServiceResponse<IReadOnlyList<FwInterface>>? resp = null;
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Loading interfaces...", async _ =>
            {
                resp = await _daemon.ListInterfacesAsync(ct);
            });

        if (resp is null || !resp.Success)
        {
            ShowDaemonError(resp?.Message ?? "Failed to load interfaces.");
            return null;
        }
        return resp.Data ?? Array.Empty<FwInterface>();
    }

    private static void RenderInterfacesTable(IReadOnlyList<FwInterface> ifaces)
    {
        if (ifaces.Count == 0)
        {
            AnsiConsole.MarkupLine("[yellow]No interfaces configured yet.[/] [dim]Pick \"Add new\" to start.[/]");
            AnsiConsole.WriteLine();
            return;
        }

        var table = new Table().Border(TableBorder.Rounded);
        table.AddColumn("Name");
        table.AddColumn("Type");
        table.AddColumn("Mode");
        table.AddColumn("IP / Mask");
        table.AddColumn("Gateway");
        table.AddColumn("MAC");
        table.AddColumn("Up");

        foreach (var i in ifaces)
        {
            var ipMask = i.IpAddress is null
                ? "[dim](unset)[/]"
                : $"{i.IpAddress}/{MaskToCidrPrefix(i.SubnetMask)}";
            table.AddRow(
                i.Name,
                i.Type,
                i.AddressingMode,
                ipMask,
                i.Gateway?.ToString() ?? "[dim]—[/]",
                i.MacAddress ?? "[dim]auto[/]",
                i.Enabled ? "[green]yes[/]" : "[red]no[/]");
        }

        AnsiConsole.Write(table);
        AnsiConsole.WriteLine();
    }

    // ── Action menu ────────────────────────────────────────────────────

    private const string AddChoice = "Add new interface (from detected NICs)";
    private const string BackChoice = "← Back to main menu";
    private const string EditPrefix = "Edit: ";
    private const string ApplyPrefix = "Apply: ";

    internal static List<string> BuildActionChoices(IReadOnlyList<FwInterface> ifaces)
    {
        var choices = new List<string> { AddChoice };
        foreach (var i in ifaces) choices.Add(EditPrefix + i.Name);
        foreach (var i in ifaces) choices.Add(ApplyPrefix + i.Name);
        choices.Add(BackChoice);
        return choices;
    }

    // ── Add ────────────────────────────────────────────────────────────

    private async Task AddInterfaceFlowAsync(CancellationToken ct)
    {
        AnsiConsole.Clear();
        AnsiConsole.Write(new Rule("[aqua]Add interface — discover[/]").LeftJustified());

        ServiceResponse<IReadOnlyList<InterfaceSuggestion>>? discResp = null;
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Probing physical NICs...", async _ =>
            {
                discResp = await _daemon.DiscoverInterfacesAsync(ct);
            });

        if (discResp is null || !discResp.Success || discResp.Data is null || discResp.Data.Count == 0)
        {
            ShowDaemonError(discResp?.Message ?? "No physical interfaces detected.");
            return;
        }

        var suggestions = discResp.Data;
        var pick = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("[bold]Pick a NIC[/]")
                .HighlightStyle(new Style(foreground: Color.Aqua))
                .AddChoices(suggestions
                    .Select(s => $"{s.Name}  [dim]({s.SuggestedType}, conf {s.Confidence}%, {(s.IsUp ? "up" : "down")})[/]")
                    .Append("← Cancel")));

        if (pick.StartsWith("←")) return;

        var pickedName = pick.Split(' ', 2)[0];
        var picked = suggestions.First(s => s.Name == pickedName);

        // Pre-populate from the suggestion so the operator only has to confirm/edit.
        var draft = new FwInterface
        {
            Name = picked.Name,
            Type = string.IsNullOrEmpty(picked.SuggestedType) ? "LAN" : picked.SuggestedType,
            Role = string.IsNullOrEmpty(picked.SuggestedRole) ? null : picked.SuggestedRole,
            IpAddress = picked.CurrentIp,
            Gateway = picked.CurrentGateway,
            MacAddress = picked.MacAddress,
            Mtu = picked.Mtu,
            AddressingMode = "static",
            Enabled = true,
            AutoStart = true
        };

        if (!await PromptInterfaceFieldsAsync(draft)) return;

        ServiceResponse<FwInterface>? createResp = null;
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Saving interface...", async _ =>
            {
                createResp = await _daemon.CreateInterfaceAsync(draft, ct);
            });

        if (createResp is null || !createResp.Success || createResp.Data is null)
        {
            ShowDaemonError(createResp?.Message ?? "Create failed.");
            return;
        }

        AnsiConsole.MarkupLine($"[green]Created[/] interface [aqua]{createResp.Data.Name}[/].");
        if (AnsiConsole.Confirm("Apply now? (writes config + brings interface up)", defaultValue: true))
        {
            await ApplyInterfaceAsync(createResp.Data, ct);
        }
        else
        {
            AnsiConsole.MarkupLine("[dim]Press any key to return.[/]");
            Console.ReadKey(intercept: true);
        }
    }

    // ── Edit ───────────────────────────────────────────────────────────

    private async Task EditInterfaceFlowAsync(FwInterface iface, CancellationToken ct)
    {
        AnsiConsole.Clear();
        AnsiConsole.Write(new Rule($"[aqua]Edit interface — {iface.Name}[/]").LeftJustified());

        if (!await PromptInterfaceFieldsAsync(iface)) return;

        ServiceResponse<FwInterface>? resp = null;
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync("Saving changes...", async _ =>
            {
                resp = await _daemon.UpdateInterfaceAsync(iface.Id, iface, ct);
            });

        if (resp is null || !resp.Success)
        {
            ShowDaemonError(resp?.Message ?? "Update failed.");
            return;
        }

        AnsiConsole.MarkupLine($"[green]Saved[/] [aqua]{iface.Name}[/].");
        if (AnsiConsole.Confirm("Apply now? (writes config + reloads interface)", defaultValue: true))
        {
            await ApplyInterfaceAsync(iface, ct);
        }
        else
        {
            AnsiConsole.MarkupLine("[dim]Changes are persisted but NOT applied. Use \"Apply\" from the menu later.[/]");
            AnsiConsole.MarkupLine("[dim]Press any key to return.[/]");
            Console.ReadKey(intercept: true);
        }
    }

    // ── Apply ──────────────────────────────────────────────────────────

    private async Task ApplyInterfaceAsync(FwInterface iface, CancellationToken ct)
    {
        if (!AnsiConsole.Confirm($"Apply [aqua]{iface.Name}[/] now? This writes /etc/* config and reloads the interface."))
            return;

        ServiceResponse<NetworkApplyResult>? resp = null;
        await AnsiConsole.Status()
            .Spinner(Spinner.Known.Dots)
            .StartAsync($"Applying {iface.Name}...", async _ =>
            {
                resp = await _daemon.ApplyInterfaceAsync(iface.Id, ct);
            });

        if (resp is null || !resp.Success)
        {
            ShowDaemonError(resp?.Message ?? "Apply failed.");
            return;
        }

        var data = resp.Data;
        AnsiConsole.MarkupLine($"[green]Applied[/] [aqua]{iface.Name}[/].");
        if (data is not null)
        {
            if (!string.IsNullOrEmpty(data.ConfigFilePath))
                AnsiConsole.MarkupLineInterpolated($"  config: {data.ConfigFilePath}");
            if (!string.IsNullOrEmpty(data.BackupFilePath))
                AnsiConsole.MarkupLineInterpolated($"  backup: {data.BackupFilePath}");
        }
        AnsiConsole.MarkupLine("[dim]Press any key to return.[/]");
        Console.ReadKey(intercept: true);
    }

    // ── Field prompts ──────────────────────────────────────────────────

    /// <summary>Returns false if the user cancelled mid-flow.</summary>
    private static Task<bool> PromptInterfaceFieldsAsync(FwInterface iface)
    {
        // Mutates iface in place — caller has the same reference.
        iface.Type = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Type")
                .AddChoices("WAN", "LAN", "DMZ", "VPN", "Management")
                .HighlightStyle(new Style(foreground: Color.Aqua)));

        iface.AddressingMode = AnsiConsole.Prompt(
            new SelectionPrompt<string>()
                .Title("Addressing mode")
                .AddChoices("static", "dhcp", "disabled")
                .HighlightStyle(new Style(foreground: Color.Aqua)));

        if (iface.AddressingMode == "static")
        {
            iface.IpAddress = PromptIp("IP address", iface.IpAddress, allowEmpty: false);
            iface.SubnetMask = PromptIp("Subnet mask", iface.SubnetMask ?? IPAddress.Parse("255.255.255.0"), allowEmpty: false);
            iface.Gateway = PromptIp("Gateway (blank for none)", iface.Gateway, allowEmpty: true);
        }
        else
        {
            // DHCP/disabled: clear the static fields so we don't carry stale values.
            iface.IpAddress = null;
            iface.SubnetMask = null;
            iface.Gateway = null;
        }

        iface.MacAddress = PromptMacAddress("MAC address (blank to keep hardware default)", iface.MacAddress);

        var mtuStr = AnsiConsole.Prompt(
            new TextPrompt<string>("MTU (blank for default)")
                .DefaultValue(iface.Mtu?.ToString() ?? string.Empty)
                .AllowEmpty()
                .Validate(s => string.IsNullOrWhiteSpace(s) || (int.TryParse(s, out var v) && v >= 68 && v <= 9216)
                    ? ValidationResult.Success()
                    : ValidationResult.Error("MTU must be 68-9216")));
        iface.Mtu = string.IsNullOrWhiteSpace(mtuStr) ? null : int.Parse(mtuStr);

        iface.Enabled = AnsiConsole.Confirm("Enabled?", defaultValue: iface.Enabled);

        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLine("[bold]Review:[/]");
        AnsiConsole.MarkupLineInterpolated($"  Name:    {iface.Name}");
        AnsiConsole.MarkupLineInterpolated($"  Type:    {iface.Type}");
        AnsiConsole.MarkupLineInterpolated($"  Mode:    {iface.AddressingMode}");
        AnsiConsole.MarkupLineInterpolated($"  IP:      {iface.IpAddress?.ToString() ?? "(unset)"}");
        AnsiConsole.MarkupLineInterpolated($"  Mask:    {iface.SubnetMask?.ToString() ?? "(unset)"}");
        AnsiConsole.MarkupLineInterpolated($"  Gateway: {iface.Gateway?.ToString() ?? "(none)"}");
        AnsiConsole.MarkupLineInterpolated($"  MAC:     {iface.MacAddress ?? "(hardware default)"}");
        AnsiConsole.MarkupLineInterpolated($"  MTU:     {iface.Mtu?.ToString() ?? "(default)"}");
        AnsiConsole.MarkupLineInterpolated($"  Enabled: {iface.Enabled}");
        AnsiConsole.WriteLine();

        return Task.FromResult(AnsiConsole.Confirm("Confirm and save?", defaultValue: true));
    }

    private static IPAddress? PromptIp(string label, IPAddress? current, bool allowEmpty)
    {
        var prompt = new TextPrompt<string>(label)
            .DefaultValue(current?.ToString() ?? string.Empty)
            .Validate(s =>
            {
                if (string.IsNullOrWhiteSpace(s))
                    return allowEmpty ? ValidationResult.Success() : ValidationResult.Error("Required");
                return IPAddress.TryParse(s, out _)
                    ? ValidationResult.Success()
                    : ValidationResult.Error("Not a valid IP address");
            });
        if (allowEmpty) prompt.AllowEmpty();
        var s = AnsiConsole.Prompt(prompt);
        return string.IsNullOrWhiteSpace(s) ? null : IPAddress.Parse(s);
    }

    private static string? PromptMacAddress(string label, string? current)
    {
        var s = AnsiConsole.Prompt(
            new TextPrompt<string>(label)
                .DefaultValue(current ?? string.Empty)
                .AllowEmpty()
                .Validate(s => string.IsNullOrWhiteSpace(s) || IsValidMac(s)
                    ? ValidationResult.Success()
                    : ValidationResult.Error("MAC must be aa:bb:cc:dd:ee:ff format")));
        return string.IsNullOrWhiteSpace(s) ? null : s.Trim().ToLowerInvariant();
    }

    internal static bool IsValidMac(string s) =>
        System.Text.RegularExpressions.Regex.IsMatch(s.Trim(), @"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$");

    // ── Util ───────────────────────────────────────────────────────────

    internal static int MaskToCidrPrefix(IPAddress? mask)
    {
        if (mask is null) return 0;
        var bytes = mask.GetAddressBytes();
        var bits = 0;
        foreach (var b in bytes)
            for (var i = 7; i >= 0; i--)
                if (((b >> i) & 1) == 1) bits++;
        return bits;
    }

    private static void ShowDaemonError(string message)
    {
        AnsiConsole.WriteLine();
        AnsiConsole.MarkupLineInterpolated($"[red]Error:[/] {message}");
        AnsiConsole.MarkupLine("[dim]Press any key to return.[/]");
        Console.ReadKey(intercept: true);
    }
}
