using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Diagnostics;
using Npgsql;
using NpgsqlTypes;

namespace NetFirewall.Services.Diagnostics;

public sealed class DiagnosticRunStore : IDiagnosticRunStore
{
    /// <summary>Results above this size are replaced by a truncation marker (one drop-log query can be large).</summary>
    public const int MaxResultBytes = 1024 * 1024;

    public static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web)
    {
        Converters = { new JsonStringEnumConverter() },
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly NpgsqlDataSource _ds;
    private readonly ILogger<DiagnosticRunStore> _logger;

    public DiagnosticRunStore(NpgsqlDataSource ds, ILogger<DiagnosticRunStore> logger)
    {
        _ds = ds;
        _logger = logger;
    }

    public async Task<Guid> StartAsync(string tool, string? target, string? requestedBy, object? parameters, CancellationToken ct = default)
    {
        var paramsJson = parameters is null ? "{}" : JsonSerializer.Serialize(parameters, parameters.GetType(), JsonOpts);

        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO diag_runs (tool, status, requested_by, target, params)
            VALUES (@tool, 'running', @by, @target, @params)
            RETURNING id", conn);
        cmd.Parameters.AddWithValue("tool", tool);
        cmd.Parameters.AddWithValue("by", (object?)Trim(requestedBy, 100) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("target", (object?)Trim(target, 255) ?? DBNull.Value);
        cmd.Parameters.Add(new NpgsqlParameter("params", NpgsqlDbType.Jsonb) { Value = paramsJson });

        var id = await cmd.ExecuteScalarAsync(ct);
        return (Guid)id!;
    }

    public async Task FinishAsync(Guid id, string status, object? result, string? summary, CancellationToken ct = default)
    {
        string? resultJson = null;
        var truncated = false;
        if (result is not null)
        {
            resultJson = JsonSerializer.Serialize(result, result.GetType(), JsonOpts);
            var bytes = Encoding.UTF8.GetByteCount(resultJson);
            if (bytes > MaxResultBytes)
            {
                _logger.LogWarning("diag run {Id}: result of {Bytes} bytes exceeds the {Max}-byte cap — storing a truncation marker", id, bytes, MaxResultBytes);
                resultJson = JsonSerializer.Serialize(new { truncated = true, bytes }, JsonOpts);
                truncated = true;
            }
        }

        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(@"
            UPDATE diag_runs
               SET status = @status,
                   finished_at = now(),
                   duration_ms = (EXTRACT(EPOCH FROM (now() - started_at)) * 1000)::int,
                   result = @result,
                   result_truncated = @truncated,
                   summary = @summary
             WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        cmd.Parameters.AddWithValue("status", status);
        cmd.Parameters.Add(new NpgsqlParameter("result", NpgsqlDbType.Jsonb) { Value = (object?)resultJson ?? DBNull.Value });
        cmd.Parameters.AddWithValue("truncated", truncated);
        cmd.Parameters.AddWithValue("summary", (object?)Trim(summary, 500) ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<DiagRun?> GetAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(Select + " WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct) ? Map(r) : null;
    }

    public async Task<(IReadOnlyList<DiagRun> Rows, int Total)> ListAsync(DiagRunFilter filter, int page, int pageSize, CancellationToken ct = default)
    {
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 1, 200);

        var where = new List<string>();
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand();
        cmd.Connection = conn;

        if (!string.IsNullOrWhiteSpace(filter.Tool))        { where.Add("tool = @tool");                cmd.Parameters.AddWithValue("tool", filter.Tool.Trim()); }
        if (!string.IsNullOrWhiteSpace(filter.Status))      { where.Add("status = @status");            cmd.Parameters.AddWithValue("status", filter.Status.Trim()); }
        if (!string.IsNullOrWhiteSpace(filter.RequestedBy)) { where.Add("requested_by = @by");          cmd.Parameters.AddWithValue("by", filter.RequestedBy.Trim()); }
        if (filter.From is { } from)                        { where.Add("started_at >= @from");         cmd.Parameters.AddWithValue("from", DateTime.SpecifyKind(from, DateTimeKind.Utc)); }
        if (filter.To is { } to)                            { where.Add("started_at < @to");            cmd.Parameters.AddWithValue("to", DateTime.SpecifyKind(to, DateTimeKind.Utc)); }

        // Window count gives the total for the pager in the same round-trip.
        cmd.CommandText = $"SELECT {Columns}, count(*) OVER() AS total FROM diag_runs"
            + (where.Count > 0 ? " WHERE " + string.Join(" AND ", where) : string.Empty)
            + " ORDER BY started_at DESC LIMIT @take OFFSET @skip";
        cmd.Parameters.AddWithValue("take", pageSize);
        cmd.Parameters.AddWithValue("skip", (page - 1) * pageSize);

        var rows = new List<DiagRun>();
        var total = 0;
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            rows.Add(Map(r));
            total = (int)r.GetInt64(r.GetOrdinal("total"));
        }
        return (rows, total);
    }

    public async Task<IReadOnlyList<DiagRun>> RecentAsync(int limit, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(Select + " ORDER BY started_at DESC LIMIT @take", conn);
        cmd.Parameters.AddWithValue("take", Math.Clamp(limit, 1, 100));
        var rows = new List<DiagRun>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct)) rows.Add(Map(r));
        return rows;
    }

    public async Task<int> PurgeOlderThanAsync(TimeSpan age, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("DELETE FROM diag_runs WHERE started_at < @cutoff", conn);
        cmd.Parameters.AddWithValue("cutoff", DateTime.UtcNow - age);
        return await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<int> PurgeAllAsync(CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("DELETE FROM diag_runs", conn);
        return await cmd.ExecuteNonQueryAsync(ct);
    }

    private const string Columns =
        "id, tool, status, started_at, finished_at, duration_ms, requested_by, target, " +
        "params::text AS params, result::text AS result, result_truncated, summary";

    private const string Select = "SELECT " + Columns + " FROM diag_runs";

    private static DiagRun Map(NpgsqlDataReader r) => new()
    {
        Id              = r.GetGuid(r.GetOrdinal("id")),
        Tool            = r.GetString(r.GetOrdinal("tool")),
        Status          = r.GetString(r.GetOrdinal("status")),
        StartedAt       = r.GetDateTime(r.GetOrdinal("started_at")),
        FinishedAt      = r.IsDBNull(r.GetOrdinal("finished_at")) ? null : r.GetDateTime(r.GetOrdinal("finished_at")),
        DurationMs      = r.IsDBNull(r.GetOrdinal("duration_ms")) ? null : r.GetInt32(r.GetOrdinal("duration_ms")),
        RequestedBy     = r.IsDBNull(r.GetOrdinal("requested_by")) ? null : r.GetString(r.GetOrdinal("requested_by")),
        Target          = r.IsDBNull(r.GetOrdinal("target")) ? null : r.GetString(r.GetOrdinal("target")),
        ParamsJson      = r.IsDBNull(r.GetOrdinal("params")) ? "{}" : r.GetString(r.GetOrdinal("params")),
        ResultJson      = r.IsDBNull(r.GetOrdinal("result")) ? null : r.GetString(r.GetOrdinal("result")),
        ResultTruncated = r.GetBoolean(r.GetOrdinal("result_truncated")),
        Summary         = r.IsDBNull(r.GetOrdinal("summary")) ? null : r.GetString(r.GetOrdinal("summary")),
    };

    private static string? Trim(string? s, int max) =>
        string.IsNullOrWhiteSpace(s) ? null : (s.Length <= max ? s : s[..max]);
}
