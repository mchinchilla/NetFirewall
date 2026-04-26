using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Auth;
using Npgsql;
using NpgsqlTypes;

namespace NetFirewall.Services.Auth;

public sealed class SessionService : ISessionService
{
    private const int TokenBytes = 32; // 256 bits — opaque cookie value
    private readonly NpgsqlDataSource _dataSource;
    private readonly ILogger<SessionService> _logger;

    public SessionService(NpgsqlDataSource dataSource, ILogger<SessionService> logger)
    {
        _dataSource = dataSource;
        _logger = logger;
    }

    public async Task<(string Token, UserSession Session)> IssueAsync(
        Guid userId, IPAddress? ip, string? userAgent, TimeSpan basicLifetime, CancellationToken ct = default)
    {
        var token = GenerateToken();
        var hash = HashToken(token);
        var now = DateTimeOffset.UtcNow;

        var session = new UserSession
        {
            Id = Guid.NewGuid(),
            UserId = userId,
            TokenHash = hash,
            AuthLevel = AuthLevels.Basic,
            CreatedAt = now,
            ExpiresAt = now.Add(basicLifetime),
            LastSeenAt = now,
            Ip = ip,
            UserAgent = userAgent
        };

        const string sql = @"
            INSERT INTO user_sessions (id, user_id, token_hash, auth_level, created_at, expires_at, last_seen_at, ip, user_agent)
            VALUES (@id, @uid, @hash, @level, @created, @expires, @seen, @ip, @ua)";

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", session.Id);
        cmd.Parameters.AddWithValue("uid", session.UserId);
        cmd.Parameters.AddWithValue("hash", session.TokenHash);
        cmd.Parameters.AddWithValue("level", session.AuthLevel);
        cmd.Parameters.AddWithValue("created", session.CreatedAt);
        cmd.Parameters.AddWithValue("expires", session.ExpiresAt);
        cmd.Parameters.AddWithValue("seen", session.LastSeenAt);
        var pip = cmd.Parameters.Add("ip", NpgsqlDbType.Inet);
        pip.Value = (object?)ip ?? DBNull.Value;
        cmd.Parameters.AddWithValue("ua", (object?)userAgent ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);

        return (token, session);
    }

    public async Task<UserSession?> ValidateAsync(string token, TimeSpan basicLifetime, CancellationToken ct = default)
    {
        if (string.IsNullOrEmpty(token)) return null;
        var hash = HashToken(token);
        var now = DateTimeOffset.UtcNow;

        // Fetch + sliding-update in one round-trip when still valid.
        const string sql = @"
            UPDATE user_sessions
               SET last_seen_at = @now,
                   expires_at = CASE
                     -- Sliding window for basic; elevated keeps its hard cap.
                     WHEN auth_level = 'basic' THEN @now + @basic
                     ELSE expires_at
                   END
             WHERE token_hash = @hash
               AND revoked_at IS NULL
               AND expires_at > @now
            RETURNING *";

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("hash", hash);
        cmd.Parameters.AddWithValue("now", now);
        cmd.Parameters.AddWithValue("basic", basicLifetime);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? Hydrate(reader) : null;
    }

    public async Task ElevateAsync(Guid sessionId, TimeSpan duration, CancellationToken ct = default)
    {
        const string sql = @"
            UPDATE user_sessions
               SET auth_level = 'elevated',
                   elevated_until = @until,
                   last_seen_at = now()
             WHERE id = @id AND revoked_at IS NULL";

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", sessionId);
        cmd.Parameters.AddWithValue("until", DateTimeOffset.UtcNow.Add(duration));
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task RevokeAsync(Guid sessionId, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "UPDATE user_sessions SET revoked_at = now() WHERE id = @id AND revoked_at IS NULL", conn);
        cmd.Parameters.AddWithValue("id", sessionId);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task RevokeAllForUserAsync(Guid userId, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "UPDATE user_sessions SET revoked_at = now() WHERE user_id = @uid AND revoked_at IS NULL", conn);
        cmd.Parameters.AddWithValue("uid", userId);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<IReadOnlyList<UserSession>> ListActiveAsync(Guid userId, CancellationToken ct = default)
    {
        const string sql = @"
            SELECT * FROM user_sessions
             WHERE user_id = @uid AND revoked_at IS NULL AND expires_at > now()
             ORDER BY last_seen_at DESC";

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("uid", userId);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var list = new List<UserSession>();
        while (await reader.ReadAsync(ct)) list.Add(Hydrate(reader));
        return list;
    }

    public async Task<int> CleanupAsync(DateTimeOffset olderThan, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "DELETE FROM user_sessions WHERE (revoked_at IS NOT NULL OR expires_at < @now) AND created_at < @cutoff", conn);
        cmd.Parameters.AddWithValue("now", DateTimeOffset.UtcNow);
        cmd.Parameters.AddWithValue("cutoff", olderThan);
        return await cmd.ExecuteNonQueryAsync(ct);
    }

    private static string GenerateToken()
    {
        Span<byte> buffer = stackalloc byte[TokenBytes];
        RandomNumberGenerator.Fill(buffer);
        return Base64UrlEncode(buffer);
    }

    /// <summary>SHA-256 of the token, hex-encoded. Used as the DB lookup key.</summary>
    public static string HashToken(string token)
    {
        Span<byte> hash = stackalloc byte[32];
        SHA256.HashData(Encoding.UTF8.GetBytes(token), hash);
        return Convert.ToHexString(hash);
    }

    private static string Base64UrlEncode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static UserSession Hydrate(NpgsqlDataReader r) => new()
    {
        Id = r.GetGuid(r.GetOrdinal("id")),
        UserId = r.GetGuid(r.GetOrdinal("user_id")),
        TokenHash = r.GetString(r.GetOrdinal("token_hash")),
        AuthLevel = r.GetString(r.GetOrdinal("auth_level")),
        ElevatedUntil = r.IsDBNull(r.GetOrdinal("elevated_until")) ? null : r.GetFieldValue<DateTimeOffset>(r.GetOrdinal("elevated_until")),
        CreatedAt = r.GetFieldValue<DateTimeOffset>(r.GetOrdinal("created_at")),
        ExpiresAt = r.GetFieldValue<DateTimeOffset>(r.GetOrdinal("expires_at")),
        LastSeenAt = r.GetFieldValue<DateTimeOffset>(r.GetOrdinal("last_seen_at")),
        Ip = r.IsDBNull(r.GetOrdinal("ip")) ? null : (IPAddress)r.GetValue(r.GetOrdinal("ip")),
        UserAgent = r.IsDBNull(r.GetOrdinal("user_agent")) ? null : r.GetString(r.GetOrdinal("user_agent")),
        RevokedAt = r.IsDBNull(r.GetOrdinal("revoked_at")) ? null : r.GetFieldValue<DateTimeOffset>(r.GetOrdinal("revoked_at"))
    };
}
