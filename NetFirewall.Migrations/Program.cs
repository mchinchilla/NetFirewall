using System.Reflection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using NetFirewall.Migrations;
using Npgsql;

// ---------------------------------------------------------------- arg parse

var (command, connectionOverride, migrationsDirOverride, autoConfirm) = ParseArgs(args);
if (command is null) return PrintHelpAndExit();

// -------------------------------------------------- configuration discovery

var connectionString = connectionOverride
                       ?? Environment.GetEnvironmentVariable("NETFIREWALL_CONN")
                       ?? ReadConnectionFromWebAppSettings();

if (string.IsNullOrEmpty(connectionString))
{
    Console.Error.WriteLine("error: no connection string. Pass --connection \"Host=...\" or set NETFIREWALL_CONN, " +
                            "or run from the repo root so NetFirewall.Web/appsettings.json is discoverable.");
    return 2;
}

var migrationsDir = migrationsDirOverride
                    ?? Path.Combine(FindRepoRoot(), "NetFirewall.Services", "sql", "migrations");

if (!Directory.Exists(migrationsDir))
{
    Console.Error.WriteLine($"error: migrations directory does not exist: {migrationsDir}");
    return 2;
}

// ---------------------------------------------------------------- bootstrap

using var loggerFactory = LoggerFactory.Create(b => b
    .AddSimpleConsole(o =>
    {
        o.SingleLine = true;
        o.IncludeScopes = false;
        o.TimestampFormat = "HH:mm:ss ";
    })
    .SetMinimumLevel(LogLevel.Information));

await using var dataSource = NpgsqlDataSource.Create(connectionString);
var runner = new MigrationRunner(dataSource, migrationsDir, loggerFactory.CreateLogger<MigrationRunner>());

// --------------------------------------------------------------- dispatch

try
{
    return command switch
    {
        "status" => await RunStatusAsync(runner),
        "up"     => await RunUpAsync(runner),
        "reset"  => await RunResetAsync(runner, autoConfirm),
        _        => PrintHelpAndExit()
    };
}
catch (MigrationDriftException dx)
{
    Console.Error.WriteLine();
    Console.Error.WriteLine("✗ DRIFT DETECTED");
    Console.Error.WriteLine("  These applied migrations have been modified on disk:");
    foreach (var d in dx.Drifted)
    {
        Console.Error.WriteLine($"    {d.Id}");
        Console.Error.WriteLine($"      applied:  {d.AppliedSha}");
        Console.Error.WriteLine($"      current:  {d.CurrentSha}");
    }
    Console.Error.WriteLine();
    Console.Error.WriteLine("  Editing applied migrations is forbidden. Write a NEW migration instead.");
    return 3;
}
catch (MigrationFailedException mf)
{
    Console.Error.WriteLine();
    Console.Error.WriteLine($"✗ {mf.Message}");
    return 4;
}
catch (Exception ex)
{
    Console.Error.WriteLine();
    Console.Error.WriteLine($"✗ {ex.GetType().Name}: {ex.Message}");
    return 5;
}

// =====================================================================

static async Task<int> RunStatusAsync(IMigrationRunner runner)
{
    var status = await runner.StatusAsync();

    Console.WriteLine();
    Console.WriteLine($"Applied:  {status.Applied.Count}");
    foreach (var a in status.Applied)
        Console.WriteLine($"  ✓ {a.Id}  ({a.AppliedAt.LocalDateTime:yyyy-MM-dd HH:mm})  {a.DurationMs} ms");

    Console.WriteLine();
    Console.WriteLine($"Pending:  {status.Pending.Count}");
    foreach (var p in status.Pending)
        Console.WriteLine($"  · {p.Id}  ({p.Sql.Length} bytes)");

    if (status.Drifted.Count > 0)
    {
        Console.WriteLine();
        Console.WriteLine($"DRIFT:    {status.Drifted.Count}  ⚠");
        foreach (var d in status.Drifted)
            Console.WriteLine($"  ! {d.Id}");
    }

    Console.WriteLine();
    return status.Drifted.Count > 0 ? 1 : 0;
}

static async Task<int> RunUpAsync(IMigrationRunner runner)
{
    var result = await runner.UpAsync();
    return result.AppliedIds.Count == 0 ? 0 : 0;
}

static async Task<int> RunResetAsync(IMigrationRunner runner, bool autoConfirm)
{
    if (!autoConfirm)
    {
        Console.Error.Write("⚠ This will DROP SCHEMA public CASCADE and re-apply every migration. Type 'reset' to confirm: ");
        var typed = Console.ReadLine();
        if (typed != "reset")
        {
            Console.Error.WriteLine("Aborted.");
            return 1;
        }
    }
    await runner.ResetAsync();
    return 0;
}

// ------------------------------------------------------- arg & config helpers

static (string? command, string? connection, string? dir, bool yes) ParseArgs(string[] args)
{
    string? command = null, connection = null, dir = null;
    var yes = false;

    for (var i = 0; i < args.Length; i++)
    {
        var a = args[i];
        switch (a)
        {
            case "status" or "up" or "reset":
                command = a;
                break;
            case "--connection" when i + 1 < args.Length:
                connection = args[++i];
                break;
            case "--dir" when i + 1 < args.Length:
                dir = args[++i];
                break;
            case "--yes" or "-y":
                yes = true;
                break;
            case "--help" or "-h":
                return (null, null, null, false);
        }
    }
    return (command, connection, dir, yes);
}

static int PrintHelpAndExit()
{
    Console.WriteLine("""
        netfirewall-migrate — Postgres schema migrations

        USAGE
          netfirewall-migrate <command> [options]

        COMMANDS
          status     Show applied / pending migrations and any drift.
          up         Apply every pending migration (in filename order).
          reset      DROP SCHEMA public CASCADE, then run up. Asks for confirmation
                     unless --yes is given. DEV ONLY — destroys all data.

        OPTIONS
          --connection "Host=...;..."   Override the connection string.
          --dir <path>                  Override the migrations directory.
          --yes / -y                    Skip the reset confirmation prompt.

        CONNECTION STRING — picked in this order:
          1. --connection "..."
          2. NETFIREWALL_CONN environment variable
          3. ConnectionStrings:DefaultConnection from NetFirewall.Web/appsettings.json
        """);
    return 0;
}

static string? ReadConnectionFromWebAppSettings()
{
    var path = Path.Combine(FindRepoRoot(), "NetFirewall.Web", "appsettings.json");
    if (!File.Exists(path)) return null;

    var config = new ConfigurationBuilder().AddJsonFile(path, optional: true).Build();
    return config.GetConnectionString("DefaultConnection");
}

static string FindRepoRoot()
{
    // Walk up from the executing assembly looking for NetFirewall.sln.
    var dir = new DirectoryInfo(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!);
    while (dir != null)
    {
        if (File.Exists(Path.Combine(dir.FullName, "NetFirewall.sln")))
            return dir.FullName;
        dir = dir.Parent;
    }
    // Fallback: cwd.
    return Directory.GetCurrentDirectory();
}
