using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Migrations;
using Npgsql;
using Testcontainers.PostgreSql;
using Xunit;

namespace NetFirewall.Tests.Infra;

/// <summary>
/// Boots one PostgreSQL container per xUnit collection (~3–6s on first hit; reused
/// across every test in the same <c>[Collection("Postgres")]</c>). Tests get an
/// <see cref="NpgsqlDataSource"/> already wired to a clean public schema; call
/// <see cref="ResetSchemaAsync"/> in a test's arrange step when you need true
/// isolation from prior tests in the same collection.
///
/// We don't use <c>Respawn</c> because the schema we test against is created
/// per-test (e.g. <c>MigrationRunner</c> tests build their own ad-hoc schemas);
/// the cheaper "drop + create" reset wins on simplicity.
/// </summary>
public sealed class PostgresFixture : IAsyncLifetime
{
    private PostgreSqlContainer? _container;
    public NpgsqlDataSource DataSource { get; private set; } = null!;
    public string ConnectionString { get; private set; } = "";

    public async Task InitializeAsync()
    {
        _container = new PostgreSqlBuilder()
            .WithImage("postgres:16-alpine")
            .WithDatabase("netfirewall_tests")
            .WithUsername("nf")
            .WithPassword("nf")
            // No persistent volume — each test run is a fresh DB.
            .Build();

        await _container.StartAsync();

        ConnectionString = _container.GetConnectionString();
        DataSource = new NpgsqlDataSourceBuilder(ConnectionString).Build();

        // Sanity: confirm we can talk to it before any test runs.
        await using var conn = await DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand("SELECT 1", conn);
        await cmd.ExecuteScalarAsync();
    }

    /// <summary>
    /// Wipes the public schema and recreates it. Cheap (~10–30 ms) and
    /// independent of any application tracking tables.
    /// </summary>
    public async Task ResetSchemaAsync()
    {
        await using var conn = await DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(
            "DROP SCHEMA IF EXISTS public CASCADE; " +
            "CREATE SCHEMA public; " +
            "GRANT ALL ON SCHEMA public TO PUBLIC; " +
            "GRANT ALL ON SCHEMA public TO CURRENT_USER;",
            conn);
        await cmd.ExecuteNonQueryAsync();
    }

    /// <summary>
    /// Applies every production migration from
    /// <c>NetFirewall.Services/sql/migrations</c> (copied next to the test
    /// binaries by the csproj). Combined with <see cref="ResetSchemaAsync"/>
    /// this gives each test a known schema baseline; ~300–600 ms once per call.
    /// </summary>
    public async Task BootstrapApplicationSchemaAsync()
    {
        var dir = Path.Combine(AppContext.BaseDirectory, "sql", "migrations");
        if (!Directory.Exists(dir))
            throw new DirectoryNotFoundException(
                $"Production migrations not found at {dir}. " +
                "Make sure NetFirewall.Tests.csproj copies sql/migrations/*.sql to output.");

        var runner = new MigrationRunner(DataSource, dir, NullLogger<MigrationRunner>.Instance);
        await runner.UpAsync();
    }

    /// <summary>
    /// Truncates every public-schema table EXCEPT <c>__migrations</c>, so the
    /// next test starts with a clean dataset but doesn't pay another full
    /// migration round-trip. Cheap (~5–20 ms).
    /// </summary>
    public async Task TruncateAppDataAsync()
    {
        await using var conn = await DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(@"
            DO $$
            DECLARE r record;
            BEGIN
                FOR r IN (
                    SELECT tablename
                      FROM pg_tables
                     WHERE schemaname = 'public' AND tablename <> '__migrations'
                ) LOOP
                    EXECUTE format('TRUNCATE TABLE public.%I RESTART IDENTITY CASCADE', r.tablename);
                END LOOP;
            END $$;", conn);
        await cmd.ExecuteNonQueryAsync();
    }

    public async Task DisposeAsync()
    {
        if (DataSource is not null) await DataSource.DisposeAsync();
        if (_container is not null) await _container.DisposeAsync();
    }
}
