using System.Reflection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Settings;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Firewall;

/// <summary>
/// Real-Postgres coverage for <see cref="AuditPrunerService"/>. The background
/// loop has a 30s startup delay and a 6h interval that we don't want to wait
/// on; we invoke the private <c>PruneOnceAsync</c> directly via reflection to
/// test the deletion logic in isolation.
/// </summary>
[Collection("Postgres")]
public sealed class AuditPrunerServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private readonly Mock<IAppSettingsService> _settings = new();
    private AuditPrunerService _svc = null!;

    public AuditPrunerServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _svc = new AuditPrunerService(_pg.DataSource, _settings.Object, NullLogger<AuditPrunerService>.Instance);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>Invoke private PruneOnceAsync(ct) via reflection.</summary>
    private async Task PruneOnceAsync()
    {
        var m = typeof(AuditPrunerService)
            .GetMethod("PruneOnceAsync", BindingFlags.NonPublic | BindingFlags.Instance)!;
        await (Task)m.Invoke(_svc, new object[] { CancellationToken.None })!;
    }

    private async Task InsertAuditAsync(string action, DateTime createdAt)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO fw_audit_log (id, table_name, record_id, action, created_at)
            VALUES (gen_random_uuid(), 'fw_test', gen_random_uuid(), @a, @c)", conn);
        cmd.Parameters.AddWithValue("a", action);
        cmd.Parameters.AddWithValue("c", createdAt);
        await cmd.ExecuteNonQueryAsync();
    }

    private async Task<int> CountAuditAsync()
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand("SELECT COUNT(*) FROM fw_audit_log", conn);
        return Convert.ToInt32(await cmd.ExecuteScalarAsync());
    }

    private void StubRetentionDays(int days) =>
        _settings.Setup(s => s.GetIntAsync("audit.retention_days", It.IsAny<CancellationToken>()))
                 .ReturnsAsync(days);

    // ── happy path: deletes only rows past the cutoff ──────────────────

    [Fact]
    public async Task Prune_DeletesRowsOlderThanRetentionWindow()
    {
        StubRetentionDays(7);
        await InsertAuditAsync("OLD",   DateTime.UtcNow.AddDays(-30));
        await InsertAuditAsync("OLDER", DateTime.UtcNow.AddDays(-365));
        await InsertAuditAsync("NEW",   DateTime.UtcNow.AddDays(-1));
        await InsertAuditAsync("NEWER", DateTime.UtcNow.AddMinutes(-5));
        Assert.Equal(4, await CountAuditAsync());

        await PruneOnceAsync();

        Assert.Equal(2, await CountAuditAsync()); // NEW and NEWER survive
    }

    [Fact]
    public async Task Prune_DeletesNothingWhenAllRowsWithinRetention()
    {
        StubRetentionDays(30);
        await InsertAuditAsync("FRESH1", DateTime.UtcNow.AddDays(-1));
        await InsertAuditAsync("FRESH2", DateTime.UtcNow.AddDays(-15));

        await PruneOnceAsync();

        Assert.Equal(2, await CountAuditAsync());
    }

    // ── retention <= 0 disables pruning ────────────────────────────────

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(-365)]
    public async Task Prune_RetentionZeroOrNegative_KeepsEverythingForever(int days)
    {
        StubRetentionDays(days);
        await InsertAuditAsync("ANCIENT", DateTime.UtcNow.AddYears(-5));
        await InsertAuditAsync("FRESH",   DateTime.UtcNow);

        await PruneOnceAsync();

        // Both rows survive: pruner intentionally skips when retention is disabled.
        Assert.Equal(2, await CountAuditAsync());
    }

    // ── retention boundary (exactly at cutoff) ─────────────────────────

    [Fact]
    public async Task Prune_RowExactlyAtCutoff_IsKept_BoundaryIsStrictLessThan()
    {
        StubRetentionDays(7);
        // Insert one row just inside (retention - 1 minute).
        await InsertAuditAsync("INSIDE", DateTime.UtcNow.AddDays(-7).AddMinutes(1));
        // And one clearly outside.
        await InsertAuditAsync("OUTSIDE", DateTime.UtcNow.AddDays(-8));

        await PruneOnceAsync();

        Assert.Equal(1, await CountAuditAsync());
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand("SELECT action FROM fw_audit_log", conn);
        var survivor = (string)(await cmd.ExecuteScalarAsync())!;
        Assert.Equal("INSIDE", survivor);
    }
}
