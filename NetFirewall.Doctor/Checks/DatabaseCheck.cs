using Npgsql;

namespace NetFirewall.Doctor.Checks;

/// <summary>
/// Database reachable with the daemon's (or web's) connection string; the server
/// is a supported PostgreSQL version (>= 14, per CLAUDE.md); the migration tracking
/// table (<c>__migrations</c>) exists; and the core domain tables are present (not
/// just the tracking table). Pending-migration / drift accounting lives in the
/// separate <see cref="MigrationsPendingCheck"/>.
/// </summary>
public sealed class DatabaseCheck : ICheck
{
    public string Category => "Database";
    public string Name => "Reachable + migrated";
    public IReadOnlyList<string> Services => new[] { "daemon", "web" };

    /// <summary>Minimum PostgreSQL major version NetFirewall supports (CLAUDE.md: "PostgreSQL 14+").</summary>
    public const int MinMajorVersion = 14;

    // A representative slice across subsystems. If these exist the schema is real,
    // not just an empty DB with a bare __migrations table.
    private static readonly string[] CoreTables =
        { "users", "dhcp_subnets", "dhcp_leases", "fw_interfaces" };

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

            // ── PostgreSQL version ──
            int major = await ServerMajorVersionAsync(c, ct);
            string verNote = major > 0 ? $"PostgreSQL {major}" : "PostgreSQL (version unknown)";
            if (major > 0 && major < MinMajorVersion)
                return CheckResult.Warn(
                    $"{verNote} is below the supported minimum (>= {MinMajorVersion})",
                    remedy: $"Upgrade PostgreSQL to {MinMajorVersion}+ (CLAUDE.md requires 14+).");

            // ── migration tracking table ──
            await using var cmd = new NpgsqlCommand(
                "SELECT to_regclass('public.__migrations') IS NOT NULL", c);
            var migrated = (bool?)await cmd.ExecuteScalarAsync(ct) ?? false;

            if (!migrated)
                return CheckResult.Warn(
                    $"{verNote}: connected, but __migrations table is absent (schema unmanaged or uninitialized)",
                    remedy: "bin/db.sh up  (or NetFirewall.Migrations) to apply the schema.");

            // ── core tables present ──
            var missing = await MissingTablesAsync(c, CoreTables, ct);
            if (missing.Count > 0)
                return CheckResult.Warn(
                    $"{verNote}: __migrations present but core tables missing: {string.Join(", ", missing)}",
                    remedy: "Schema is partially applied. Run bin/db.sh status, then bin/db.sh up.");

            return CheckResult.Pass($"{verNote}: __migrations + core tables present");
        }
        catch (Exception ex)
        {
            return CheckResult.Fail($"DB unreachable: {ex.Message}",
                remedy: "Verify PostgreSQL is up and the connection string (host/user/password/db) is correct.");
        }
    }

    private static async Task<int> ServerMajorVersionAsync(NpgsqlConnection c, CancellationToken ct)
    {
        try
        {
            // server_version_num is an integer like 140012 (14.12) / 160004 (16.4).
            await using var cmd = new NpgsqlCommand("SHOW server_version_num", c);
            var raw = (string?)await cmd.ExecuteScalarAsync(ct);
            return int.TryParse(raw, out var n) ? n / 10000 : 0;
        }
        catch { return 0; }
    }

    private static async Task<List<string>> MissingTablesAsync(NpgsqlConnection c, string[] tables, CancellationToken ct)
    {
        var missing = new List<string>();
        foreach (var t in tables)
        {
            await using var cmd = new NpgsqlCommand("SELECT to_regclass(@n) IS NOT NULL", c);
            cmd.Parameters.AddWithValue("n", $"public.{t}");
            var exists = (bool?)await cmd.ExecuteScalarAsync(ct) ?? false;
            if (!exists) missing.Add(t);
        }
        return missing;
    }
}
