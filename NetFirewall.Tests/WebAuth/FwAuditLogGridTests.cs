using Microsoft.Extensions.DependencyInjection;
using NetFirewall.Services.Firewall;
using NetFirewall.Tests.Infra;
using NetFirewall.Web.Grids;
using NetFirewall.Web.Grids.Firewall;
using NetOpenGrid.Application.Binding;
using NetOpenGrid.Infrastructure.Runtime;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// The audit log is a NetOpenGrid grid pushed down to PostgreSQL (AuditLogGridSource). Runs the
/// real grid runtime over real rows: the Action checklist filter, the Table filter and the date
/// filter must reach the SQL. Replaces the old Table-action tests, whose bug (binding a parameter
/// named "action" to the MVC action name, so every search matched nothing) this still guards.
/// </summary>
[Collection("Postgres")]
public sealed class FwAuditLogGridTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private IGridRuntime _grid = null!;

    public FwAuditLogGridTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();

        await using (var conn = await _pg.DataSource.OpenConnectionAsync())
        await using (var cmd = new NpgsqlCommand(@"
            INSERT INTO fw_audit_log (table_name, record_id, action, user_id, created_at) VALUES
              ('fw_filter_rules', uuid_generate_v4(), 'INSERT', 'admin', now() - interval '1 hour'),
              ('fw_filter_rules', uuid_generate_v4(), 'UPDATE', 'admin', now() - interval '2 hours'),
              ('fw_nat_rules',    uuid_generate_v4(), 'DELETE', 'ops',   now() - interval '3 hours'),
              ('fw_nat_rules',    uuid_generate_v4(), 'INSERT', NULL,    now() - interval '10 days')", conn))
        {
            await cmd.ExecuteNonQueryAsync();
        }

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IAuditLogGridSource>(new AuditLogGridSource(_pg.DataSource));
        services.AddNetFirewallGrids();
        _grid = services.BuildServiceProvider().GetRequiredKeyedService<IGridRuntime>(FwAuditLogGrid.Id);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private Task<GridRowsResponse> RowsAsync(params (string Key, string Value)[] query) =>
        _grid.RenderRowsAsync(new GridRequestValues(query
            .GroupBy(q => q.Key)
            .Select(g => new KeyValuePair<string, IReadOnlyList<string>>(g.Key, g.Select(x => x.Value).ToArray())))).AsTask();

    [Fact]
    public async Task NoFilter_ListsEveryEntry()
        => Assert.Equal(4, (await RowsAsync()).TotalCount);

    [Fact]
    public async Task ActionFilter_ReachesTheSql()
        => Assert.Equal(2, (await RowsAsync(("filter", "action:in:[\"INSERT\"]"))).TotalCount);

    [Fact]
    public async Task TableAndActionFilters_Combine()
        => Assert.Equal(1, (await RowsAsync(("filter", "table:equals:fw_nat_rules"), ("filter", "action:in:[\"DELETE\"]"))).TotalCount);

    [Fact]
    public async Task DefaultView_IsTheLast24Hours()
    {
        var q = FwAuditLogGrid.DefaultQuery(DateTime.UtcNow);
        var pairs = q.Split('&').Select(p => p.Split('=', 2)).Select(kv => (kv[0], Uri.UnescapeDataString(kv[1]))).ToArray();
        Assert.Equal(3, (await RowsAsync(pairs)).TotalCount);
    }
}
