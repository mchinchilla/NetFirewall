using System.Text.Json;
using NetFirewall.Doctor;
using NetFirewall.Doctor.Checks;
using Spectre.Console;

// ── arg parsing ──
//   --json                  machine-readable output
//   --service <name>        filter checks by category/service (web|daemon|dhcp|tui|all)
//   --prefix <path>         override install prefix (default /opt/netfirewall)
//   --etc <path>            override config dir (default /etc/netfirewall)
//   --help / -h             usage
if (args.Contains("--help") || args.Contains("-h"))
{
    PrintHelp();
    return 0;
}

var asJson = args.Contains("--json");
string? serviceFilter = ArgValue(args, "--service");
if (string.Equals(serviceFilter, "all", StringComparison.OrdinalIgnoreCase)) serviceFilter = null;
var prefix = ArgValue(args, "--prefix");
var etc = ArgValue(args, "--etc");

var ctx = DoctorContext.Build(prefix, etc);

// All checks. Each is self-contained + fail-soft.
var checks = new ICheck[]
{
    new EnvFilesCheck(),
    new RequiredVarsCheck("daemon", c => c.DaemonEnv, c => c.DaemonEnvPath,
        "ConnectionStrings__DefaultConnection", "NETFIREWALL_MASTER_KEY", "Daemon__SocketPath"),
    new RequiredVarsCheck("web", c => c.WebEnv, c => c.WebEnvPath,
        "ConnectionStrings__DefaultConnection", "NETFIREWALL_MASTER_KEY", "ASPNETCORE_URLS", "Daemon__Enabled"),
    new MasterKeySyncCheck(),
    new PathsCheck(),
    new DhcpPathsCheck(),
    new SystemdUnitsCheck(),
    new DaemonSocketCheck(),
    new DhcpConfigCheck(),
    new DhcpInterfaceCheck(),
    new DhcpListeningCheck(),
    new DiagnosticToolsCheck(),
    new DatabaseCheck(),
    new MigrationsPendingCheck(),
    new DhcpDatabaseCheck(),
};

var selected = checks.Where(c =>
    serviceFilter is null ||
    c.Services.Count == 0 ||
    c.Services.Any(s => string.Equals(s, serviceFilter, StringComparison.OrdinalIgnoreCase))).ToArray();

using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
var results = new List<(ICheck Check, CheckResult Result)>();
foreach (var check in selected)
{
    CheckResult r;
    try { r = await check.RunAsync(ctx, cts.Token); }
    catch (Exception ex) { r = CheckResult.Fail($"{check.Name} threw: {ex.Message}"); } // belt-and-suspenders
    results.Add((check, r));
}

int failures = results.Count(x => x.Result.Status == CheckStatus.Fail);

if (asJson)
{
    var payload = results.Select(x => new
    {
        category = x.Check.Category,
        name = x.Check.Name,
        status = x.Result.Status.ToString().ToLowerInvariant(),
        message = x.Result.Message,
        remedy = x.Result.Remedy,
        detail = x.Result.Detail,
    });
    Console.WriteLine(JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
}
else
{
    Render(results);
}

return failures > 0 ? 1 : 0;

// ── rendering ──
static void Render(List<(ICheck Check, CheckResult Result)> results)
{
    AnsiConsole.Write(new Rule("[bold]NetFirewall Doctor[/]").LeftJustified());

    var table = new Table().Border(TableBorder.Rounded).Expand();
    table.AddColumn("");
    table.AddColumn("Category");
    table.AddColumn("Check");
    table.AddColumn("Result");
    table.AddColumn("Remedy");

    foreach (var (check, r) in results)
    {
        var (glyph, color) = r.Status switch
        {
            CheckStatus.Pass => ("[green]✓[/]", "green"),
            CheckStatus.Warn => ("[yellow]⚠[/]", "yellow"),
            CheckStatus.Fail => ("[red]✗[/]", "red"),
            _ => ("[dim]–[/]", "dim"),
        };
        var msg = $"[{color}]{Markup.Escape(r.Message)}[/]";
        var remedy = r.Status is CheckStatus.Pass or CheckStatus.Skip || string.IsNullOrEmpty(r.Remedy)
            ? "[dim]—[/]"
            : Markup.Escape(r.Remedy);
        table.AddRow(glyph, $"[dim]{Markup.Escape(check.Category)}[/]", Markup.Escape(check.Name), msg, remedy);
    }

    AnsiConsole.Write(table);

    int pass = results.Count(x => x.Result.Status == CheckStatus.Pass);
    int warn = results.Count(x => x.Result.Status == CheckStatus.Warn);
    int fail = results.Count(x => x.Result.Status == CheckStatus.Fail);
    int skip = results.Count(x => x.Result.Status == CheckStatus.Skip);

    var summary = $"[green]{pass} passed[/]  [red]{fail} failed[/]  [yellow]{warn} warnings[/]  [dim]{skip} skipped[/]";
    var panelColor = fail > 0 ? Color.Red : warn > 0 ? Color.Yellow : Color.Green;
    AnsiConsole.Write(new Panel(summary).BorderColor(panelColor).Header(fail > 0 ? " PROBLEMS FOUND " : " OK "));
}

static string? ArgValue(string[] args, string flag)
{
    var i = Array.IndexOf(args, flag);
    return i >= 0 && i + 1 < args.Length ? args[i + 1] : null;
}

static void PrintHelp() => Console.WriteLine("""
    netfirewall-doctor — validate a NetFirewall deployment

    USAGE
      netfirewall-doctor [options]

    Runs every requirements check against this host and prints a table of
    pass / warn / fail / skip with a remedy for anything that is not passing.
    Read-only: it inspects files, units, sockets and the database, and changes
    nothing. install.sh runs it as the post-install verification step.

    OPTIONS
      --service <name>   Only checks for one service: web | daemon | dhcp | tui | all.
                         Checks that belong to no service always run. Default: all.
      --json             Emit the results as JSON instead of a table (for CI).
      --prefix <path>    Installation prefix to inspect.   Default: /opt/netfirewall
      --etc <path>       Configuration directory.          Default: /etc/netfirewall
      --help, -h         Show this help.

    EXIT STATUS
      0   No check failed (warnings and skips do not fail the run).
      1   At least one check failed.

    NOTES
      Linux-only checks report "skipped" on other platforms rather than failing.
      The production prefix on some deployments is /opt/tekium — pass --prefix
      when it differs from the default.

    EXAMPLES
      netfirewall-doctor
      netfirewall-doctor --service dhcp
      netfirewall-doctor --prefix /opt/tekium --etc /etc/netfirewall
      netfirewall-doctor --json | jq '.[] | select(.status == "fail")'

    SEE ALSO
      docs/doctor.md, netfirewall-tui(1), netfirewall-migrate --help
    """);
