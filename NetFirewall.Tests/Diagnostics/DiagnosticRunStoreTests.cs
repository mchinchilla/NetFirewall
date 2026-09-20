using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Diagnostics;
using NetFirewall.Tests.Infra;

namespace NetFirewall.Tests.Diagnostics;

/// <summary>Real Postgres: proves migration 00041 applies and the store round-trips rows.</summary>
[Collection("Postgres")]
public sealed class DiagnosticRunStoreTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private DiagnosticRunStore _store = null!;

    public DiagnosticRunStoreTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _store = new DiagnosticRunStore(_pg.DataSource, NullLogger<DiagnosticRunStore>.Instance);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>jsonb re-serialises on output (spaces, key order) — always compare parsed values.</summary>
    private static JsonElement Json(string json) => JsonDocument.Parse(json).RootElement;

    [Fact]
    public async Task Start_ThenFinish_RoundTripsStatusResultAndDuration()
    {
        var id = await _store.StartAsync(DiagTools.Ping, "1.1.1.1", "marvin", new PingRequest("1.1.1.1", Fwmark: "0x500"));

        var running = await _store.GetAsync(id);
        Assert.NotNull(running);
        Assert.Equal(DiagRunStatus.Running, running.Status);
        Assert.Equal("marvin", running.RequestedBy);
        Assert.Equal("0x500", Json(running.ParamsJson).GetProperty("fwmark").GetString());
        Assert.Null(running.FinishedAt);

        var result = new PingResult("1.1.1.1", "1.1.1.1", "fwmark 0x500", 3, 3, 0, 40.1, 41.0, 42.2,
            new[] { new PingReply(1, 55, 40.1) }, "raw");
        await _store.FinishAsync(id, DiagRunStatus.Ok, result, "3/3 replies");

        var done = await _store.GetAsync(id);
        Assert.NotNull(done);
        Assert.Equal(DiagRunStatus.Ok, done.Status);
        Assert.NotNull(done.FinishedAt);
        Assert.NotNull(done.DurationMs);
        Assert.False(done.ResultTruncated);
        Assert.Equal(41.0, Json(done.ResultJson!).GetProperty("rttAvgMs").GetDouble());
        Assert.Equal("3/3 replies", done.Summary);
    }

    [Fact]
    public async Task EnumsAreStoredByName_AndNullsOmitted()
    {
        var id = await _store.StartAsync(DiagTools.VpnDoctor, "wg0", null, null);
        var report = new DiagReport(DiagTools.VpnDoctor, "wg0", DateTime.UtcNow, 12, new[]
        {
            DiagCheck.Fail("if.address", "Interface", "Address", "live .3 ≠ configured .2", new DiagRemedy("Apply VPN", "/Vpn/WireGuard")),
        });

        await _store.FinishAsync(id, report.RunStatus, report, report.Summary);

        var row = await _store.GetAsync(id);
        Assert.Equal(DiagRunStatus.Fail, row!.Status);
        var check = Json(row.ResultJson!).GetProperty("checks")[0];
        Assert.Equal("Fail", check.GetProperty("status").GetString());          // enum by name
        Assert.False(check.TryGetProperty("detail", out _));                    // nulls omitted
    }

    [Fact]
    public async Task OversizedResult_IsReplacedByTruncationMarker()
    {
        var id = await _store.StartAsync(DiagTools.DropLog, null, null, null);
        var huge = new { lines = Enumerable.Repeat(new string('x', 1024), 1100).ToArray() }; // > 1 MiB

        await _store.FinishAsync(id, DiagRunStatus.Ok, huge, "huge");

        var row = await _store.GetAsync(id);
        Assert.True(row!.ResultTruncated);
        Assert.True(Json(row.ResultJson!).GetProperty("truncated").GetBoolean());
        Assert.True(row.ResultJson!.Length < 200);
    }

    [Fact]
    public async Task List_FiltersByToolAndStatus_AndCountsTotal()
    {
        var a = await _store.StartAsync(DiagTools.Ping, "a", "u1", null);
        var b = await _store.StartAsync(DiagTools.Ping, "b", "u2", null);
        var c = await _store.StartAsync(DiagTools.RouteGet, "c", "u1", null);
        await _store.FinishAsync(a, DiagRunStatus.Ok, null, null);
        await _store.FinishAsync(b, DiagRunStatus.Fail, null, null);
        await _store.FinishAsync(c, DiagRunStatus.Ok, null, null);

        var (pings, pingTotal) = await _store.ListAsync(new DiagRunFilter(Tool: DiagTools.Ping), page: 1, pageSize: 10);
        Assert.Equal(2, pingTotal);
        Assert.All(pings, r => Assert.Equal(DiagTools.Ping, r.Tool));

        var (failed, failedTotal) = await _store.ListAsync(new DiagRunFilter(Status: DiagRunStatus.Fail), 1, 10);
        Assert.Equal(1, failedTotal);
        Assert.Equal(b, failed.Single().Id);

        var (byUser, userTotal) = await _store.ListAsync(new DiagRunFilter(RequestedBy: "u1"), 1, 10);
        Assert.Equal(2, userTotal);
        Assert.Equal(2, byUser.Count);

        var (page2, total) = await _store.ListAsync(new DiagRunFilter(), page: 2, pageSize: 2);
        Assert.Equal(3, total);
        Assert.Single(page2);

        var recent = await _store.RecentAsync(2);
        Assert.Equal(2, recent.Count);
    }

    [Fact]
    public async Task Purge_RemovesOldRows_AndPurgeAll_Empties()
    {
        var id = await _store.StartAsync(DiagTools.Sysctl, null, null, null);
        Assert.Equal(0, await _store.PurgeOlderThanAsync(TimeSpan.FromDays(1))); // brand new → kept
        Assert.NotNull(await _store.GetAsync(id));

        Assert.Equal(1, await _store.PurgeOlderThanAsync(TimeSpan.Zero)); // everything before "now"
        Assert.Null(await _store.GetAsync(id));

        await _store.StartAsync(DiagTools.Sysctl, null, null, null);
        Assert.Equal(1, await _store.PurgeAllAsync());
    }
}
