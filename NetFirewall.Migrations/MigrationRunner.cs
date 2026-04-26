using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace NetFirewall.Migrations;

public sealed class MigrationRunner : IMigrationRunner
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly string _migrationsDir;
    private readonly ILogger<MigrationRunner> _logger;

    public MigrationRunner(NpgsqlDataSource dataSource, string migrationsDir, ILogger<MigrationRunner> logger)
    {
        _dataSource = dataSource;
        _migrationsDir = migrationsDir;
        _logger = logger;
    }

    // ------------------------------------------------------------------ status

    public async Task<MigrationStatus> StatusAsync(CancellationToken ct = default)
    {
        await EnsureTrackingTableAsync(ct);

        var onDisk = LoadFromDisk();
        var applied = await LoadAppliedAsync(ct);
        var appliedIds = applied.Select(a => a.Id).ToHashSet();

        var pending = onDisk.Where(m => !appliedIds.Contains(m.Id)).ToList();

        var byId = onDisk.ToDictionary(m => m.Id);
        var drifted = applied
            .Where(a => byId.TryGetValue(a.Id, out var disk) && disk.Sha256 != a.Sha256)
            .Select(a => new DriftedMigration(a.Id, a.Sha256, byId[a.Id].Sha256))
            .ToList();

        return new MigrationStatus(applied, pending, drifted);
    }

    // ---------------------------------------------------------------------- up

    public async Task<UpResult> UpAsync(CancellationToken ct = default)
    {
        var status = await StatusAsync(ct);

        if (status.Drifted.Count > 0)
        {
            // Refuse to proceed when an already-applied migration has been
            // edited — the caller needs to write a NEW migration instead.
            throw new MigrationDriftException(status.Drifted);
        }

        if (status.Pending.Count == 0)
        {
            _logger.LogInformation("Schema up to date — {Count} migrations already applied.", status.Applied.Count);
            return new UpResult(Array.Empty<string>(), Array.Empty<DriftedMigration>());
        }

        var applied = new List<string>();
        foreach (var m in status.Pending)
        {
            await ApplyOneAsync(m, ct);
            applied.Add(m.Id);
        }

        _logger.LogInformation("Applied {Count} migration(s).", applied.Count);
        return new UpResult(applied, Array.Empty<DriftedMigration>());
    }

    // ------------------------------------------------------------------- reset

    public async Task<UpResult> ResetAsync(CancellationToken ct = default)
    {
        _logger.LogWarning("RESET requested — dropping public schema and re-applying every migration.");

        await using (var conn = await _dataSource.OpenConnectionAsync(ct))
        await using (var cmd = new NpgsqlCommand(
            // Default privs vary by install — re-grant to PUBLIC + the connecting role
            // so the freshly-created schema is usable immediately.
            "DROP SCHEMA IF EXISTS public CASCADE; " +
            "CREATE SCHEMA public; " +
            "GRANT ALL ON SCHEMA public TO PUBLIC; " +
            "GRANT ALL ON SCHEMA public TO CURRENT_USER;",
            conn))
        {
            await cmd.ExecuteNonQueryAsync(ct);
        }

        return await UpAsync(ct);
    }

    // ----------------------------------------------------------------- helpers

    private async Task EnsureTrackingTableAsync(CancellationToken ct)
    {
        const string sql = @"
            CREATE TABLE IF NOT EXISTS __migrations (
                id           text                     PRIMARY KEY,
                applied_at   timestamp with time zone NOT NULL DEFAULT now(),
                sha256       text                     NOT NULL,
                duration_ms  int                      NOT NULL
            )";
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private async Task<List<AppliedMigration>> LoadAppliedAsync(CancellationToken ct)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "SELECT id, applied_at, sha256, duration_ms FROM __migrations ORDER BY id", conn);
        await using var reader = await cmd.ExecuteReaderAsync(ct);

        var list = new List<AppliedMigration>();
        while (await reader.ReadAsync(ct))
        {
            list.Add(new AppliedMigration(
                reader.GetString(0),
                reader.GetFieldValue<DateTimeOffset>(1),
                reader.GetString(2),
                reader.GetInt32(3)));
        }
        return list;
    }

    private List<Migration> LoadFromDisk()
    {
        if (!Directory.Exists(_migrationsDir))
            throw new DirectoryNotFoundException($"Migrations directory not found: {_migrationsDir}");

        var files = Directory.GetFiles(_migrationsDir, "*.sql")
            .OrderBy(p => Path.GetFileName(p), StringComparer.Ordinal)
            .ToList();

        return files.Select(path =>
        {
            var sql = File.ReadAllText(path);
            var id = Path.GetFileNameWithoutExtension(path);
            var sha = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(sql))).ToLowerInvariant();
            return new Migration(id, path, sql, sha);
        }).ToList();
    }

    private async Task ApplyOneAsync(Migration m, CancellationToken ct)
    {
        _logger.LogInformation("Applying {Id} ({Bytes} bytes) …", m.Id, m.Sql.Length);

        var sw = Stopwatch.StartNew();
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        try
        {
            await using (var cmd = new NpgsqlCommand(m.Sql, conn, tx))
            {
                await cmd.ExecuteNonQueryAsync(ct);
            }

            await using (var record = new NpgsqlCommand(
                "INSERT INTO __migrations (id, sha256, duration_ms) VALUES (@id, @sha, @ms)", conn, tx))
            {
                record.Parameters.AddWithValue("id", m.Id);
                record.Parameters.AddWithValue("sha", m.Sha256);
                record.Parameters.AddWithValue("ms", (int)sw.ElapsedMilliseconds);
                await record.ExecuteNonQueryAsync(ct);
            }

            await tx.CommitAsync(ct);
            sw.Stop();
            _logger.LogInformation("  ✓ {Id} applied in {Ms} ms", m.Id, sw.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            await tx.RollbackAsync(ct);
            _logger.LogError(ex, "  ✗ {Id} FAILED — transaction rolled back.", m.Id);
            throw new MigrationFailedException(m.Id, ex);
        }
    }
}

public sealed class MigrationDriftException : Exception
{
    public IReadOnlyList<DriftedMigration> Drifted { get; }

    public MigrationDriftException(IReadOnlyList<DriftedMigration> drifted)
        : base($"{drifted.Count} previously-applied migration(s) have been modified on disk. " +
               "Editing an applied migration is not allowed — write a NEW migration instead.")
    {
        Drifted = drifted;
    }
}

public sealed class MigrationFailedException : Exception
{
    public string MigrationId { get; }

    public MigrationFailedException(string id, Exception inner)
        : base($"Migration {id} failed: {inner.Message}", inner)
    {
        MigrationId = id;
    }
}
