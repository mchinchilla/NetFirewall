using Npgsql;

namespace NetFirewall.Doctor.Checks;

/// <summary>
/// Database reachable with the daemon's connection string, and the migration
/// tracking table (<c>__migrations</c>) exists. Doesn't compute pending migrations
/// (that needs the runner's file list) — just confirms the schema was initialized.
/// </summary>
public sealed class DatabaseCheck : ICheck
{
    public string Category => "Database";
    public string Name => "Reachable + migrated";
    public IReadOnlyList<string> Services => new[] { "daemon", "web" };

    public async Task<CheckResult> RunAsync(DoctorContext ctx, CancellationToken ct)
    {
        var conn = ctx.DaemonEnv?.GetValueOrDefault("ConnectionStrings__DefaultConnection")
                 ?? ctx.WebEnv?.GetValueOrDefault("ConnectionStrings__DefaultConnection");

        if (string.IsNullOrWhiteSpace(conn) || conn.Contains("__REPLACE__"))
            return CheckResult.Skip("no connection string in env files (see Required vars)");

        try
        {
            await using var c = new NpgsqlConnection(conn);
            await c.OpenAsync(ct);

            await using var cmd = new NpgsqlCommand(
                "SELECT to_regclass('public.__migrations') IS NOT NULL", c);
            var migrated = (bool?)await cmd.ExecuteScalarAsync(ct) ?? false;

            if (!migrated)
                return CheckResult.Warn(
                    "connected, but __migrations table is absent (schema may be unmanaged or uninitialized)",
                    remedy: "bin/db.sh up  (or NetFirewall.Migrations) to apply the schema.");

            return CheckResult.Pass("connected; __migrations present");
        }
        catch (Exception ex)
        {
            return CheckResult.Fail($"DB unreachable: {ex.Message}",
                remedy: "Verify PostgreSQL is up and the connection string (host/user/password/db) is correct.");
        }
    }
}
