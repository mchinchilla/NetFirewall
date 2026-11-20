using System.Net;
using System.Net.NetworkInformation;
using System.Text.Json;
using BenchmarkDotNet.Attributes;
using NetFirewall.Models.Dhcp;
using Npgsql;
using NpgsqlTypes;
using NetFirewall.Services.Dhcp;
using RepoDb;

namespace NetFirewall.Benchmarks;

/// <summary>
/// The LeaseCache write-behind flush: N lease upserts (renewals — every row conflicts on
/// mac_address, the common case) in one transaction, against REAL PostgreSQL, two ways:
/// <list type="bullet">
/// <item><b>NpgsqlBatch</b> — today: N <c>INSERT … ON CONFLICT</c> statements, one round trip.</item>
/// <item><b>SetBasedShipped</b> — what LeaseCache now sends: one <c>INSERT … SELECT FROM unnest(…) ON CONFLICT</c>.</item>
/// </list>
/// Runs in schema <c>nf_bench</c> (a copy of dhcp_leases), never touching the dev data.
/// Connection: env NETFIREWALL_BENCH_CONN, else NetFirewall.Web/appsettings.json.
/// </summary>
[MemoryDiagnoser]
public class LeaseFlushBenchmarks
{
    private NpgsqlDataSource _ds = null!;
    private List<DhcpLease> _rows = null!;
    private int _round;

    [Params(1, 10, 100)]
    public int N { get; set; }

    [GlobalSetup]
    public async Task Setup()
    {
        GlobalConfiguration.Setup().UsePostgreSql();
        var cs = new NpgsqlConnectionStringBuilder(ConnectionString()) { SearchPath = "nf_bench,public" };
        _ds = NpgsqlDataSource.Create(cs.ConnectionString);
        await using (var c = await _ds.OpenConnectionAsync())
        await using (var cmd = new NpgsqlCommand("""
            CREATE SCHEMA IF NOT EXISTS nf_bench;
            DROP TABLE IF EXISTS nf_bench.dhcp_leases;
            CREATE TABLE nf_bench.dhcp_leases (LIKE public.dhcp_leases INCLUDING ALL);
            """, c))
            await cmd.ExecuteNonQueryAsync();

        _rows = Enumerable.Range(0, 1000).Select(i => new DhcpLease
        {
            Id = Guid.NewGuid(),
            MacAddress = new PhysicalAddress([0x02, 0x00, 0x00, 0x00, (byte)(i >> 8), (byte)i]),
            IpAddress = new IPAddress([10, 60, (byte)(i >> 8), (byte)i]),
            Hostname = $"host-{i}",
            StartTime = DateTime.UtcNow, EndTime = DateTime.UtcNow.AddHours(1),
        }).ToList();
        await NpgsqlBatchFlush(_rows);                 // seed: every later flush is a renewal (conflict)
    }

    [GlobalCleanup]
    public async Task Cleanup()
    {
        await using (var c = await _ds.OpenConnectionAsync())
        await using (var cmd = new NpgsqlCommand("DROP SCHEMA IF EXISTS nf_bench CASCADE", c))
            await cmd.ExecuteNonQueryAsync();
        await _ds.DisposeAsync();
    }

    private List<DhcpLease> Next()
    {
        var start = (_round++ * N) % (1000 - N);
        var now = DateTime.UtcNow;
        var slice = _rows.GetRange(start, N);
        foreach (var l in slice) { l.StartTime = now; l.EndTime = now.AddHours(1); }
        return slice;
    }

    [Benchmark(Baseline = true)]
    public Task NpgsqlBatch() => NpgsqlBatchFlush(Next());

    /// <summary>The shipped flush: <see cref="LeaseCache.SetBasedCommands"/> (coalesce per MAC → one unnest upsert).</summary>
    [Benchmark]
    public async Task SetBasedShipped()
    {
        var ops = Next().Select(l => new LeaseWriteOperation
        {
            Type = LeaseWriteType.Upsert, MacAddress = l.MacAddress.ToString(), IpAddress = l.IpAddress,
            Hostname = l.Hostname, StartTime = l.StartTime, EndTime = l.EndTime,
        }).ToList();
        await using var conn = await _ds.OpenConnectionAsync();
        await using var tx = await conn.BeginTransactionAsync();
        await using (var batch = new Npgsql.NpgsqlBatch(conn, tx))
        {
            foreach (var c in LeaseCache.SetBasedCommands(ops)) batch.BatchCommands.Add(c);
            await batch.ExecuteNonQueryAsync();
        }
        await tx.CommitAsync();
    }

    // RepoDb BulkMerge (binary COPY → pseudo table → merge) was measured too and is NOT here:
    // RepoDb.PostgreSql.BulkOperations 1.17 throws a NullReferenceException inside
    // GetMergeCommandText for dhcp_leases (both merge modes, schema-qualified or not), and the
    // BinaryBulk* names are obsolete in 1.17. COPY + temp table only pays off well above a
    // flush's ≤ 100 rows anyway. Plain BulkInsert (imports) works.

    private async Task NpgsqlBatchFlush(List<DhcpLease> rows)
    {
        await using var conn = await _ds.OpenConnectionAsync();
        await using var tx = await conn.BeginTransactionAsync();
        await using (var batch = new Npgsql.NpgsqlBatch(conn, tx))
        {
            foreach (var r in rows)
            {
                var c = new NpgsqlBatchCommand("""
                    INSERT INTO dhcp_leases (id, mac_address, ip_address, hostname, start_time, end_time)
                    VALUES ($1, $2::macaddr, $3, $4, $5, $6)
                    ON CONFLICT (mac_address) DO UPDATE SET ip_address = EXCLUDED.ip_address, hostname = EXCLUDED.hostname,
                        start_time = EXCLUDED.start_time, end_time = EXCLUDED.end_time
                    """);
                c.Parameters.Add(new NpgsqlParameter { Value = r.Id });
                c.Parameters.Add(new NpgsqlParameter { Value = r.MacAddress.ToString() });
                c.Parameters.Add(new NpgsqlParameter { Value = r.IpAddress });
                c.Parameters.Add(new NpgsqlParameter { Value = (object?)r.Hostname ?? DBNull.Value });
                c.Parameters.Add(new NpgsqlParameter { Value = r.StartTime });
                c.Parameters.Add(new NpgsqlParameter { Value = r.EndTime });
                batch.BatchCommands.Add(c);
            }
            await batch.ExecuteNonQueryAsync();
        }
        await tx.CommitAsync();
    }

    private static string ConnectionString()
    {
        if (Environment.GetEnvironmentVariable("NETFIREWALL_BENCH_CONN") is { Length: > 0 } env) return env;
        for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            var path = Path.Combine(dir.FullName, "NetFirewall.Web", "appsettings.json");
            if (!File.Exists(path)) continue;
            using var doc = JsonDocument.Parse(File.ReadAllText(path));
            return doc.RootElement.GetProperty("ConnectionStrings").GetProperty("DefaultConnection").GetString()!;
        }
        throw new InvalidOperationException("Set NETFIREWALL_BENCH_CONN or run from inside the repo.");
    }
}
