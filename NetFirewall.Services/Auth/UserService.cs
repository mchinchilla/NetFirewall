using System.Net;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Auth;
using Npgsql;
using NpgsqlTypes;

namespace NetFirewall.Services.Auth;

public sealed class UserService : IUserService
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly ILogger<UserService> _logger;

    public UserService(NpgsqlDataSource dataSource, ILogger<UserService> logger)
    {
        _dataSource = dataSource;
        _logger = logger;
    }

    public async Task<User?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("SELECT * FROM users WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? Hydrate(reader) : null;
    }

    public async Task<User?> GetByUsernameAsync(string username, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("SELECT * FROM users WHERE username = @u", conn);
        cmd.Parameters.AddWithValue("u", username);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? Hydrate(reader) : null;
    }

    public async Task<IReadOnlyList<User>> ListAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("SELECT * FROM users ORDER BY username", conn);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        var users = new List<User>();
        while (await reader.ReadAsync(ct)) users.Add(Hydrate(reader));
        return users;
    }

    public async Task<int> CountAsync(CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("SELECT COUNT(*) FROM users", conn);
        return Convert.ToInt32(await cmd.ExecuteScalarAsync(ct));
    }

    public async Task<User> CreateAsync(User user, CancellationToken ct = default)
    {
        if (!UserRoles.IsValid(user.Role))
            throw new ArgumentException($"Invalid role '{user.Role}'", nameof(user));

        user.Id = user.Id == Guid.Empty ? Guid.NewGuid() : user.Id;
        user.CreatedAt = user.UpdatedAt = DateTimeOffset.UtcNow;

        const string sql = @"
            INSERT INTO users (id, username, email, password_hash, role, is_active, created_at, updated_at)
            VALUES (@id, @username, @email, @hash, @role, @active, @created, @updated)";

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", user.Id);
        cmd.Parameters.AddWithValue("username", user.Username);
        cmd.Parameters.AddWithValue("email", (object?)user.Email ?? DBNull.Value);
        cmd.Parameters.AddWithValue("hash", user.PasswordHash);
        cmd.Parameters.AddWithValue("role", user.Role);
        cmd.Parameters.AddWithValue("active", user.IsActive);
        cmd.Parameters.AddWithValue("created", user.CreatedAt);
        cmd.Parameters.AddWithValue("updated", user.UpdatedAt);
        await cmd.ExecuteNonQueryAsync(ct);
        return user;
    }

    public async Task UpdatePasswordHashAsync(Guid id, string newHash, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "UPDATE users SET password_hash = @h, updated_at = now() WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("h", newHash);
        cmd.Parameters.AddWithValue("id", id);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<User> UpdateProfileAsync(Guid id, UserProfileUpdate update, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        const string sql = @"
            UPDATE users SET
                first_name   = @first,
                last_name    = @last,
                display_name = @display,
                email        = @email,
                phone        = @phone,
                timezone     = COALESCE(@tz,     timezone),
                locale       = COALESCE(@locale, locale),
                updated_at   = now()
            WHERE id = @id
            RETURNING *";
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);
        cmd.Parameters.AddWithValue("first",   (object?)Trim(update.FirstName)   ?? DBNull.Value);
        cmd.Parameters.AddWithValue("last",    (object?)Trim(update.LastName)    ?? DBNull.Value);
        cmd.Parameters.AddWithValue("display", (object?)Trim(update.DisplayName) ?? DBNull.Value);
        cmd.Parameters.AddWithValue("email",   (object?)Trim(update.Email)       ?? DBNull.Value);
        cmd.Parameters.AddWithValue("phone",   (object?)Trim(update.Phone)       ?? DBNull.Value);
        cmd.Parameters.AddWithValue("tz",      (object?)Trim(update.Timezone)    ?? DBNull.Value);
        cmd.Parameters.AddWithValue("locale",  (object?)Trim(update.Locale)      ?? DBNull.Value);

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct))
            throw new InvalidOperationException($"User {id} not found.");
        return Hydrate(reader);
    }

    private static string? Trim(string? s) => string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    public async Task SetActiveAsync(Guid id, bool active, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "UPDATE users SET is_active = @a, updated_at = now() WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("a", active);
        cmd.Parameters.AddWithValue("id", id);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task SetRoleAsync(Guid id, string role, CancellationToken ct = default)
    {
        if (!UserRoles.IsValid(role)) throw new ArgumentException($"Invalid role '{role}'", nameof(role));

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "UPDATE users SET role = @r, updated_at = now() WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("r", role);
        cmd.Parameters.AddWithValue("id", id);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task RecordLoginSuccessAsync(Guid id, IPAddress? ip, CancellationToken ct = default)
    {
        const string sql = @"
            UPDATE users SET
              failed_login_count = 0,
              locked_until = NULL,
              last_login_at = now(),
              last_login_ip = @ip,
              updated_at = now()
            WHERE id = @id";

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);
        var p = cmd.Parameters.Add("ip", NpgsqlDbType.Inet);
        p.Value = (object?)ip ?? DBNull.Value;
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<bool> RecordLoginFailureAsync(Guid id, IPAddress? ip, int threshold, TimeSpan lockDuration, CancellationToken ct = default)
    {
        // Increment counter atomically; if we crossed the threshold, set lock.
        const string sql = @"
            UPDATE users SET
              failed_login_count = failed_login_count + 1,
              locked_until = CASE
                WHEN failed_login_count + 1 >= @threshold THEN now() + @lock
                ELSE locked_until
              END,
              updated_at = now()
            WHERE id = @id
            RETURNING failed_login_count, locked_until";

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);
        cmd.Parameters.AddWithValue("threshold", threshold);
        cmd.Parameters.AddWithValue("lock", lockDuration);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return false;

        var count = reader.GetInt32(0);
        var locked = !reader.IsDBNull(1);
        if (locked) _logger.LogWarning("User {Id} locked after {Count} failed logins from {Ip}", id, count, ip);
        return locked;
    }

    private static User Hydrate(NpgsqlDataReader r) => new()
    {
        Id = r.GetGuid(r.GetOrdinal("id")),
        Username = r.GetString(r.GetOrdinal("username")),
        Email = r.IsDBNull(r.GetOrdinal("email")) ? null : r.GetString(r.GetOrdinal("email")),
        PasswordHash = r.GetString(r.GetOrdinal("password_hash")),
        Role = r.GetString(r.GetOrdinal("role")),
        IsActive = r.GetBoolean(r.GetOrdinal("is_active")),
        FailedLoginCount = r.GetInt32(r.GetOrdinal("failed_login_count")),
        LockedUntil = r.IsDBNull(r.GetOrdinal("locked_until")) ? null : r.GetFieldValue<DateTimeOffset>(r.GetOrdinal("locked_until")),
        LastLoginAt = r.IsDBNull(r.GetOrdinal("last_login_at")) ? null : r.GetFieldValue<DateTimeOffset>(r.GetOrdinal("last_login_at")),
        LastLoginIp = r.IsDBNull(r.GetOrdinal("last_login_ip")) ? null : (IPAddress)r.GetValue(r.GetOrdinal("last_login_ip")),
        CreatedAt = r.GetFieldValue<DateTimeOffset>(r.GetOrdinal("created_at")),
        UpdatedAt = r.GetFieldValue<DateTimeOffset>(r.GetOrdinal("updated_at")),
        FirstName    = SafeStr(r, "first_name"),
        LastName     = SafeStr(r, "last_name"),
        DisplayName  = SafeStr(r, "display_name"),
        Phone        = SafeStr(r, "phone"),
        Timezone     = SafeStr(r, "timezone") ?? "UTC",
        Locale       = SafeStr(r, "locale")   ?? "en"
    };

    /// <summary>Tolerant of pre-migration DBs where the column doesn't exist yet.</summary>
    private static string? SafeStr(NpgsqlDataReader r, string col)
    {
        try
        {
            var ord = r.GetOrdinal(col);
            return r.IsDBNull(ord) ? null : r.GetString(ord);
        }
        catch (IndexOutOfRangeException)
        {
            return null;
        }
    }
}
