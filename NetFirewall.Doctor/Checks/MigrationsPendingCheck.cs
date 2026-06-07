using System.Security.Cryptography;
using Npgsql;

namespace NetFirewall.Doctor.Checks;

/// <summary>
/// No pending or drifted migrations: every <c>.sql</c> file on disk has been applied
/// (its id is in <c>__migrations</c>) and no applied file's content has changed since
/// (sha256 matches). Mirrors NetFirewall.Migrations' runner logic without taking a
/// dependency on it — the comparison is intentionally a small, self-contained copy.
/// </summary>
public sealed class MigrationsPendingCheck : ICheck
{
    public string Category => "Database";
    public string Name => "Migrations up to date";
    public IReadOnlyList<string> Services => new[] { "daemon", "web" };

    public async Task<CheckResult> RunAsync(DoctorContext ctx, CancellationToken ct)
    {
        var conn = ctx.DaemonEnv?.GetValueOrDefault("ConnectionStrings__DefaultConnection")
                 ?? ctx.WebEnv?.GetValueOrDefault("ConnectionStrings__DefaultConnection");
        if (string.IsNullOrWhiteSpace(conn) || conn.Contains("__REPLACE__"))
            return CheckResult.Skip("no connection string in env files (see Required vars)");

        var dir = ctx.MigrationsDir;
        if (!Directory.Exists(dir))
            return CheckResult.Skip($"migration files not found ({dir}) — can't compute pending set");

        IReadOnlyList<(string Id, string Sha)> onDisk;
        try { onDisk = LoadOnDisk(dir); }
        catch (Exception ex) { return CheckResult.Skip($"could not read migration files: {ex.Message}"); }

        if (onDisk.Count == 0)
            return CheckResult.Skip($"no .sql files under {dir}");

        try
        {
            await using var c = new NpgsqlConnection(conn);
            await c.OpenAsync(ct);

            var hasTable = (bool?)await new NpgsqlCommand(
                "SELECT to_regclass('public.__migrations') IS NOT NULL", c).ExecuteScalarAsync(ct) ?? false;
            if (!hasTable)
                return CheckResult.Warn(
                    $"__migrations absent; all {onDisk.Count} migration(s) are pending",
                    remedy: "bin/db.sh up to apply the schema.");

            var applied = new Dictionary<string, string>(StringComparer.Ordinal);
            await using (var cmd = new NpgsqlCommand("SELECT id, sha256 FROM __migrations", c))
            await using (var r = await cmd.ExecuteReaderAsync(ct))
                while (await r.ReadAsync(ct))
                    applied[r.GetString(0)] = r.GetString(1);

            var (pending, drifted) = Compare(onDisk, applied);

            if (drifted.Count > 0)
                return CheckResult.Fail(
                    $"{drifted.Count} applied migration(s) drifted (content changed): {Join(drifted)}",
                    remedy: "NEVER edit an applied migration. Revert the edits, or write a new NNNNN_*.sql to fix forward.");

            if (pending.Count > 0)
                return CheckResult.Warn(
                    $"{pending.Count} pending migration(s): {Join(pending)}",
                    remedy: "bin/db.sh up  (or NetFirewall.Migrations) to apply them.");

            return CheckResult.Pass($"all {onDisk.Count} migration(s) applied; no drift");
        }
        catch (Exception ex)
        {
            return CheckResult.Fail($"could not read __migrations: {ex.Message}",
                remedy: "Verify PostgreSQL is reachable and the role can read public.__migrations.");
        }
    }

    private static string Join(IReadOnlyList<string> ids) =>
        ids.Count <= 5 ? string.Join(", ", ids) : string.Join(", ", ids.Take(5)) + $", … (+{ids.Count - 5})";

    /// <summary>Load (id, sha256) for every .sql file, in filename order — matching the runner.</summary>
    internal static IReadOnlyList<(string Id, string Sha)> LoadOnDisk(string dir) =>
        Directory.EnumerateFiles(dir, "*.sql")
            .OrderBy(Path.GetFileName, StringComparer.Ordinal)
            .Select(p => (Path.GetFileNameWithoutExtension(p), Sha256(File.ReadAllText(p))))
            .ToList();

    /// <summary>Pure diff of on-disk files vs the applied (id→sha) map. Pending = not applied;
    /// drifted = applied but sha differs. Testable without a DB.</summary>
    internal static (List<string> Pending, List<string> Drifted) Compare(
        IReadOnlyList<(string Id, string Sha)> onDisk,
        IReadOnlyDictionary<string, string> applied)
    {
        var pending = new List<string>();
        var drifted = new List<string>();
        foreach (var (id, sha) in onDisk)
        {
            if (!applied.TryGetValue(id, out var appliedSha)) pending.Add(id);
            else if (!string.Equals(appliedSha, sha, StringComparison.Ordinal)) drifted.Add(id);
        }
        return (pending, drifted);
    }

    private static string Sha256(string text)
    {
        var bytes = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(text));
        return Convert.ToHexStringLower(bytes);
    }
}
