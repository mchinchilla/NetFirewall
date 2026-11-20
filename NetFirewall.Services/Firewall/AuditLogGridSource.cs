using Npgsql;
using NetFirewall.Models.Firewall;
using NetOpenGrid.Application.Options;
using NetOpenGrid.Domain.Abstractions;
using NetOpenGrid.Persistence.Npgsql;

namespace NetFirewall.Services.Firewall;

/// <summary>
/// One <c>fw_audit_log</c> row as the Audit log grid reads it. Mapped by
/// <see cref="NpgsqlGridDataSource{TRow}"/> through the projection's quoted <c>AS</c> aliases
/// (by name, parameterless constructor, settable properties — no <c>[Map]</c>). The before/after
/// JSON is deliberately not here: it is fetched per row for the expanded detail.
/// </summary>
public sealed class AuditLogGridRow
{
    public Guid Id { get; set; }
    public DateTime CreatedAt { get; set; }
    public string TableName { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public Guid RecordId { get; set; }
    public string? UserId { get; set; }
}

/// <summary>
/// Server-side data for the Audit log grid. The table grows without bound, so filter, sort,
/// value counts, paging and the total all run in PostgreSQL (NetOpenGrid's Npgsql push-down)
/// instead of over an in-memory snapshot. Singleton: the grid runtime that calls
/// <see cref="Create"/> is itself a singleton resolved from the root provider.
/// </summary>
public interface IAuditLogGridSource
{
    /// <summary>Data source bound to <paramref name="options"/> (field ids from <see cref="AuditLogGridFields"/>).</summary>
    IGridDataSource<AuditLogGridRow> Create(GridOptions<AuditLogGridRow> options);

    /// <summary>One entry with its before/after JSON, for the row detail. Null when it no longer exists.</summary>
    Task<FwAuditLog?> GetEntryAsync(Guid id, CancellationToken ct = default);
}

/// <summary>Grid field ids — the keys of the SQL whitelist; the Web grid's columns must use exactly these.</summary>
public static class AuditLogGridFields
{
    public const string Created = "created";
    public const string Table = "table";
    public const string Action = "action";
    public const string Record = "record";
    public const string User = "user";
}

public sealed class AuditLogGridSource : IAuditLogGridSource
{
    // The one SELECT of the grid (no WHERE / ORDER BY / LIMIT — the builder appends them).
    // created_at is nullable in 00004 (DEFAULT now() only), so the projection COALESCEs it
    // for the non-nullable DateTime property; filters and sorts use the bare column so the
    // idx_fw_audit_log_created index still serves "newest first" and "since". user_id is
    // COALESCEd to '' in both places so the User checklist's blank entry filters to those rows.
    private const string Projection = """
        SELECT a.id AS "Id",
               COALESCE(a.created_at, 'epoch'::timestamptz) AS "CreatedAt",
               a.table_name AS "TableName",
               a.action AS "Action",
               a.record_id AS "RecordId",
               COALESCE(a.user_id, '') AS "UserId"
        FROM fw_audit_log a
        """;

    private static readonly GridSqlMap Map = new(
        Projection,
        BaseWhere: "TRUE",
        Columns: new Dictionary<string, GridSqlColumn>(StringComparer.Ordinal)
        {
            [AuditLogGridFields.Created] = new("a.created_at", typeof(DateTime), "CreatedAt"),
            [AuditLogGridFields.Table] = new("a.table_name", typeof(string), "TableName", Searchable: true),
            [AuditLogGridFields.Action] = new("a.action", typeof(string), "Action", Searchable: true),
            [AuditLogGridFields.Record] = new("a.record_id", typeof(Guid), "RecordId", Searchable: true),
            [AuditLogGridFields.User] = new("COALESCE(a.user_id, '')", typeof(string), "UserId", Searchable: true),
        },
        DefaultOrderBy: "a.created_at DESC, a.id DESC",
        MaxGroupingRows: 5000,
        CountCap: 10_000);

    private readonly NpgsqlDataSource _dataSource;

    public AuditLogGridSource(NpgsqlDataSource dataSource) => _dataSource = dataSource;

    public IGridDataSource<AuditLogGridRow> Create(GridOptions<AuditLogGridRow> options) =>
        new NpgsqlGridDataSource<AuditLogGridRow>(_dataSource, Map, options);

    public async Task<FwAuditLog?> GetEntryAsync(Guid id, CancellationToken ct = default)
    {
        const string sql = """
            SELECT id, table_name, record_id, action, old_values::text, new_values::text, user_id, created_at
            FROM fw_audit_log WHERE id = @id
            """;
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null;
        return new FwAuditLog
        {
            Id = reader.GetGuid(0),
            TableName = reader.GetString(1),
            RecordId = reader.GetGuid(2),
            Action = reader.GetString(3),
            OldValues = reader.IsDBNull(4) ? null : reader.GetString(4),
            NewValues = reader.IsDBNull(5) ? null : reader.GetString(5),
            UserId = reader.IsDBNull(6) ? null : reader.GetString(6),
            CreatedAt = reader.IsDBNull(7) ? DateTime.MinValue : reader.GetDateTime(7),
        };
    }
}
