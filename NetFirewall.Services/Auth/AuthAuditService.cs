using System.Net;
using System.Text.Json;
using NetFirewall.Models.Auth;
using Npgsql;
using NpgsqlTypes;

namespace NetFirewall.Services.Auth;

public sealed class AuthAuditService : IAuthAuditService
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
    private readonly NpgsqlDataSource _dataSource;

    public AuthAuditService(NpgsqlDataSource dataSource) => _dataSource = dataSource;

    public async Task LogAsync(
        string eventType,
        Guid? userId = null,
        string? username = null,
        IPAddress? ip = null,
        string? userAgent = null,
        object? detail = null,
        CancellationToken ct = default)
    {
        const string sql = @"
            INSERT INTO auth_audit_log (event_type, user_id, username, ip, user_agent, detail)
            VALUES (@evt, @uid, @uname, @ip, @ua, @detail::jsonb)";

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("evt", eventType);
        cmd.Parameters.AddWithValue("uid", (object?)userId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("uname", (object?)username ?? DBNull.Value);
        var pip = cmd.Parameters.Add("ip", NpgsqlDbType.Inet);
        pip.Value = (object?)ip ?? DBNull.Value;
        cmd.Parameters.AddWithValue("ua", (object?)userAgent ?? DBNull.Value);
        cmd.Parameters.AddWithValue("detail",
            detail is null ? (object)DBNull.Value : JsonSerializer.Serialize(detail, JsonOpts));
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<IReadOnlyList<AuthAuditEntry>> RecentAsync(int limit = 100, CancellationToken ct = default)
    {
        const string sql = @"SELECT * FROM auth_audit_log ORDER BY occurred_at DESC LIMIT @lim";

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("lim", limit);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var list = new List<AuthAuditEntry>();
        while (await reader.ReadAsync(ct))
        {
            list.Add(new AuthAuditEntry
            {
                Id = reader.GetInt64(reader.GetOrdinal("id")),
                OccurredAt = reader.GetFieldValue<DateTimeOffset>(reader.GetOrdinal("occurred_at")),
                UserId = reader.IsDBNull(reader.GetOrdinal("user_id")) ? null : reader.GetGuid(reader.GetOrdinal("user_id")),
                Username = reader.IsDBNull(reader.GetOrdinal("username")) ? null : reader.GetString(reader.GetOrdinal("username")),
                EventType = reader.GetString(reader.GetOrdinal("event_type")),
                Ip = reader.IsDBNull(reader.GetOrdinal("ip")) ? null : (IPAddress)reader.GetValue(reader.GetOrdinal("ip")),
                UserAgent = reader.IsDBNull(reader.GetOrdinal("user_agent")) ? null : reader.GetString(reader.GetOrdinal("user_agent")),
                Detail = reader.IsDBNull(reader.GetOrdinal("detail")) ? null : reader.GetString(reader.GetOrdinal("detail"))
            });
        }
        return list;
    }
}
