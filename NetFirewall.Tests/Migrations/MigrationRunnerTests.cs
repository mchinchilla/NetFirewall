using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Migrations;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Migrations;

/// <summary>
/// Forward-only migration runner backed by a real Postgres container. Each test
/// owns its own ad-hoc migrations directory and resets the public schema first,
/// so they remain order-independent within the collection.
/// </summary>
[Collection("Postgres")]
public sealed class MigrationRunnerTests : IAsyncLifetime, IDisposable
{
    private readonly PostgresFixture _pg;
    private readonly string _migrationsDir;

    public MigrationRunnerTests(PostgresFixture pg)
    {
        _pg = pg;
        _migrationsDir = Path.Combine(
            Path.GetTempPath(),
            "nf-migrations-tests-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_migrationsDir);
    }

    public async Task InitializeAsync() => await _pg.ResetSchemaAsync();
    public Task DisposeAsync() => Task.CompletedTask;
    public void Dispose()
    {
        try { Directory.Delete(_migrationsDir, recursive: true); } catch { /* best-effort */ }
    }

    private MigrationRunner CreateRunner() =>
        new(_pg.DataSource, _migrationsDir, NullLogger<MigrationRunner>.Instance);

    private void WriteMigration(string id, string sql) =>
        File.WriteAllText(Path.Combine(_migrationsDir, $"{id}.sql"), sql);

    private async Task<int> CountAsync(string table)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand($"SELECT COUNT(*) FROM {table}", conn);
        return Convert.ToInt32(await cmd.ExecuteScalarAsync());
    }

    private async Task<bool> TableExistsAsync(string name)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=@n)", conn);
        cmd.Parameters.AddWithValue("n", name);
        return (bool)(await cmd.ExecuteScalarAsync())!;
    }

    // ── status: empty / initial ────────────────────────────────────────

    [Fact]
    public async Task Status_OnEmptyDb_ReportsAllPending_AndNoApplied()
    {
        WriteMigration("00001_a", "CREATE TABLE a (id int);");
        WriteMigration("00002_b", "CREATE TABLE b (id int);");

        var status = await CreateRunner().StatusAsync();

        Assert.Empty(status.Applied);
        Assert.Equal(2, status.Pending.Count);
        Assert.Equal(new[] { "00001_a", "00002_b" }, status.Pending.Select(p => p.Id));
        Assert.Empty(status.Drifted);
    }

    [Fact]
    public async Task Status_CreatesTrackingTableOnFirstCall()
    {
        WriteMigration("00001_x", "CREATE TABLE x (id int);");
        Assert.False(await TableExistsAsync("__migrations"));

        await CreateRunner().StatusAsync();

        Assert.True(await TableExistsAsync("__migrations"));
    }

    // ── up: applies in filename order ──────────────────────────────────

    [Fact]
    public async Task Up_AppliesAllPending_InFilenameOrder()
    {
        // Write deliberately out-of-order so we can verify ordering by filename, not by enumeration.
        WriteMigration("00010_late", "CREATE TABLE late (id int);");
        WriteMigration("00002_mid",  "CREATE TABLE mid (id int);");
        WriteMigration("00001_early","CREATE TABLE early (id int);");

        var result = await CreateRunner().UpAsync();

        Assert.Equal(new[] { "00001_early", "00002_mid", "00010_late" }, result.AppliedIds);
        Assert.True(await TableExistsAsync("early"));
        Assert.True(await TableExistsAsync("mid"));
        Assert.True(await TableExistsAsync("late"));
        Assert.Equal(3, await CountAsync("__migrations"));
    }

    [Fact]
    public async Task Up_RecordsShaAndDuration()
    {
        WriteMigration("00001_meta", "CREATE TABLE meta (id int);");
        await CreateRunner().UpAsync();

        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand("SELECT id, sha256, duration_ms FROM __migrations", conn);
        await using var reader = await cmd.ExecuteReaderAsync();
        Assert.True(await reader.ReadAsync());

        Assert.Equal("00001_meta", reader.GetString(0));
        Assert.Matches("^[0-9a-f]{64}$", reader.GetString(1));
        Assert.True(reader.GetInt32(2) >= 0);
    }

    [Fact]
    public async Task Up_IsIdempotent_NothingHappensWhenNoPending()
    {
        WriteMigration("00001_only", "CREATE TABLE only_t (id int);");
        await CreateRunner().UpAsync();
        Assert.Equal(1, await CountAsync("__migrations"));

        var second = await CreateRunner().UpAsync();
        Assert.Empty(second.AppliedIds);
        Assert.Equal(1, await CountAsync("__migrations"));
    }

    // ── drift detection ────────────────────────────────────────────────

    [Fact]
    public async Task Status_DetectsDriftWhenAppliedFileWasEdited()
    {
        WriteMigration("00001_d", "CREATE TABLE d (id int);");
        await CreateRunner().UpAsync();

        // Edit the SQL on disk after it was applied.
        WriteMigration("00001_d", "CREATE TABLE d (id int, modified bool);");

        var status = await CreateRunner().StatusAsync();

        Assert.Single(status.Drifted);
        var drift = status.Drifted[0];
        Assert.Equal("00001_d", drift.Id);
        Assert.NotEqual(drift.AppliedSha, drift.CurrentSha);
    }

    [Fact]
    public async Task Up_RefusesToProceedWhenDriftDetected()
    {
        WriteMigration("00001_d", "CREATE TABLE d (id int);");
        await CreateRunner().UpAsync();
        WriteMigration("00001_d", "CREATE TABLE d (id int, oops bool);");
        // Add a clean pending migration too — should NOT get applied because drift halts the world.
        WriteMigration("00002_clean", "CREATE TABLE clean (id int);");

        var ex = await Assert.ThrowsAsync<MigrationDriftException>(() => CreateRunner().UpAsync());
        Assert.Single(ex.Drifted);
        Assert.False(await TableExistsAsync("clean")); // pending migration never ran
        Assert.Equal(1, await CountAsync("__migrations"));
    }

    // ── failed migration: transaction rollback ─────────────────────────

    [Fact]
    public async Task Up_FailedMigration_RollsBackWithinItsTransaction()
    {
        // Two statements: the CREATE succeeds, then a syntax error fails.
        // Both must be undone together since the runner wraps the file in BEGIN..COMMIT.
        WriteMigration("00001_ok",   "CREATE TABLE ok_t (id int);");
        WriteMigration("00002_bad",  "CREATE TABLE half (id int); SELECT this_is_a_syntax_error;");
        WriteMigration("00003_late", "CREATE TABLE late_t (id int);");

        var ex = await Assert.ThrowsAsync<MigrationFailedException>(() => CreateRunner().UpAsync());

        Assert.Equal("00002_bad", ex.MigrationId);
        Assert.True(await TableExistsAsync("ok_t"));   // first migration committed
        Assert.False(await TableExistsAsync("half"));  // bad migration rolled back
        Assert.False(await TableExistsAsync("late_t"));// third never ran
        Assert.Equal(1, await CountAsync("__migrations")); // only 00001 recorded
    }

    [Fact]
    public async Task Up_FailedMigrationCanBeFixedAndReapplied()
    {
        WriteMigration("00001_bad", "BOGUS SQL;");
        await Assert.ThrowsAsync<MigrationFailedException>(() => CreateRunner().UpAsync());
        Assert.Equal(0, await CountAsync("__migrations"));

        // Fix the file (changes its sha — but it never recorded so no drift).
        WriteMigration("00001_bad", "CREATE TABLE fixed (id int);");

        var result = await CreateRunner().UpAsync();
        Assert.Equal(new[] { "00001_bad" }, result.AppliedIds);
        Assert.True(await TableExistsAsync("fixed"));
    }

    // ── reset ──────────────────────────────────────────────────────────

    [Fact]
    public async Task Reset_DropsSchemaAndReappliesEverything()
    {
        WriteMigration("00001_r1", "CREATE TABLE r1 (id int);");
        WriteMigration("00002_r2", "CREATE TABLE r2 (id int);");
        await CreateRunner().UpAsync();
        // Insert some user data so we can confirm reset wipes it.
        await using (var conn = await _pg.DataSource.OpenConnectionAsync())
        await using (var insert = new NpgsqlCommand("INSERT INTO r1 (id) VALUES (42)", conn))
            await insert.ExecuteNonQueryAsync();
        Assert.Equal(1, await CountAsync("r1"));

        var result = await CreateRunner().ResetAsync();

        Assert.Equal(2, result.AppliedIds.Count);
        Assert.True(await TableExistsAsync("r1"));
        Assert.Equal(0, await CountAsync("r1")); // user data wiped
        Assert.Equal(2, await CountAsync("__migrations"));
    }

    [Fact]
    public async Task Reset_ClearsDriftStateBecauseTrackingTableIsAlsoDropped()
    {
        WriteMigration("00001_d", "CREATE TABLE d (id int);");
        await CreateRunner().UpAsync();
        WriteMigration("00001_d", "CREATE TABLE d (id int, dirty bool);"); // drift!

        // Reset re-creates the tracking table, then re-applies the (now-current) file
        // from scratch — drift "vanishes" because we never had a prior recorded sha.
        var result = await CreateRunner().ResetAsync();

        Assert.Equal(new[] { "00001_d" }, result.AppliedIds);
        var status = await CreateRunner().StatusAsync();
        Assert.Empty(status.Drifted);
    }

    // ── load-from-disk edge cases ──────────────────────────────────────

    [Fact]
    public async Task Status_ThrowsWhenMigrationsDirectoryMissing()
    {
        var runner = new MigrationRunner(
            _pg.DataSource,
            Path.Combine(Path.GetTempPath(), "definitely-not-a-real-dir-" + Guid.NewGuid()),
            NullLogger<MigrationRunner>.Instance);

        await Assert.ThrowsAsync<DirectoryNotFoundException>(() => runner.StatusAsync());
    }

    [Fact]
    public async Task LoadFromDisk_IgnoresNonSqlFiles()
    {
        WriteMigration("00001_real", "CREATE TABLE real_t (id int);");
        File.WriteAllText(Path.Combine(_migrationsDir, "README.md"), "not a migration");
        File.WriteAllText(Path.Combine(_migrationsDir, "00002_draft.sql.bak"), "not a migration either");

        var status = await CreateRunner().StatusAsync();

        Assert.Single(status.Pending);
        Assert.Equal("00001_real", status.Pending[0].Id);
    }

    // ── sha-256 stability ──────────────────────────────────────────────

    [Fact]
    public async Task Sha256_IsStableForSameContents_AcrossRuns()
    {
        WriteMigration("00001_sha", "CREATE TABLE sha_t (id int);");
        await CreateRunner().UpAsync();

        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand("SELECT sha256 FROM __migrations WHERE id = '00001_sha'", conn);
        var stored = (string)(await cmd.ExecuteScalarAsync())!;

        // Re-compute independently from the same byte sequence.
        var bytes = System.Text.Encoding.UTF8.GetBytes("CREATE TABLE sha_t (id int);");
        var expected = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bytes)).ToLowerInvariant();

        Assert.Equal(expected, stored);
    }
}
