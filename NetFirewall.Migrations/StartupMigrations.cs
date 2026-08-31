using Microsoft.Extensions.Logging;
using Npgsql;

namespace NetFirewall.Migrations;

/// <summary>
/// Apply pending SQL migrations at process start. The daemon (and the Web,
/// so a standalone Web still isn't a schema version behind) call this before
/// serving traffic. <see cref="MigrationRunner.UpAsync"/> is idempotent:
/// already-applied files are skipped; drift still fails the process.
/// </summary>
public static class StartupMigrations
{
    public static async Task ApplyAsync(
        NpgsqlDataSource dataSource,
        ILoggerFactory loggerFactory,
        string? contentRoot = null,
        CancellationToken ct = default)
    {
        var dir = ResolveDirectory(contentRoot);
        if (dir is null)
        {
            throw new DirectoryNotFoundException(
                "Could not find sql/migrations. Publish copies them next to the binary " +
                "(sql/migrations/*.sql); from the repo they live under " +
                "NetFirewall.Services/sql/migrations.");
        }

        var log = loggerFactory.CreateLogger("StartupMigrations");
        log.LogInformation("Applying pending schema migrations from {Dir}", dir);

        var runner = new MigrationRunner(
            dataSource, dir, loggerFactory.CreateLogger<MigrationRunner>());
        var result = await runner.UpAsync(ct);

        if (result.AppliedIds.Count > 0)
            log.LogInformation("Applied {Count} migration(s): {Ids}",
                result.AppliedIds.Count, string.Join(", ", result.AppliedIds));
    }

    /// <summary>
    /// Locate the folder of <c>NNNNN_*.sql</c> files. Publish layout first,
    /// then in-repo, then the installer paths.
    /// </summary>
    public static string? ResolveDirectory(string? contentRoot = null)
    {
        foreach (var candidate in Candidates(contentRoot))
        {
            if (Directory.Exists(candidate)
                && Directory.EnumerateFiles(candidate, "*.sql").Any())
                return Path.GetFullPath(candidate);
        }
        return null;
    }

    private static IEnumerable<string> Candidates(string? contentRoot)
    {
        yield return Path.Combine(AppContext.BaseDirectory, "sql", "migrations");
        if (!string.IsNullOrEmpty(contentRoot))
        {
            yield return Path.Combine(contentRoot, "sql", "migrations");
            var dir = new DirectoryInfo(contentRoot);
            for (var i = 0; i < 6 && dir is not null; i++, dir = dir.Parent)
            {
                yield return Path.Combine(dir.FullName, "NetFirewall.Services", "sql", "migrations");
            }
        }
        yield return "/opt/tekium/migrations/sql/migrations";
        yield return "/opt/netfirewall/migrations/sql/migrations";
    }
}
