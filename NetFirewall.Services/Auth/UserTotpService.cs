using Microsoft.Extensions.Logging;
using NetFirewall.Models.Auth;
using Npgsql;

namespace NetFirewall.Services.Auth;

public sealed class UserTotpService : IUserTotpService
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly ITotpService _totp;
    private readonly ITotpSecretCipher _cipher;
    private readonly ILogger<UserTotpService> _logger;

    public UserTotpService(
        NpgsqlDataSource dataSource,
        ITotpService totp,
        ITotpSecretCipher cipher,
        ILogger<UserTotpService> logger)
    {
        _dataSource = dataSource;
        _totp = totp;
        _cipher = cipher;
        _logger = logger;
    }

    public async Task<bool> HasEnrolledAsync(Guid userId, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("SELECT 1 FROM user_totp_secrets WHERE user_id = @uid", conn);
        cmd.Parameters.AddWithValue("uid", userId);
        var v = await cmd.ExecuteScalarAsync(ct);
        return v != null;
    }

    public async Task<UserTotpSecret?> GetAsync(Guid userId, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("SELECT * FROM user_totp_secrets WHERE user_id = @uid", conn);
        cmd.Parameters.AddWithValue("uid", userId);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        if (!await reader.ReadAsync(ct)) return null;
        return new UserTotpSecret
        {
            UserId = reader.GetGuid(reader.GetOrdinal("user_id")),
            SecretEncrypted = (byte[])reader["secret_encrypted"],
            EnrolledAt = reader.GetFieldValue<DateTimeOffset>(reader.GetOrdinal("enrolled_at")),
            LastUsedAt = reader.IsDBNull(reader.GetOrdinal("last_used_at")) ? null : reader.GetFieldValue<DateTimeOffset>(reader.GetOrdinal("last_used_at")),
            LastUsedStep = reader.IsDBNull(reader.GetOrdinal("last_used_step")) ? null : reader.GetInt64(reader.GetOrdinal("last_used_step"))
        };
    }

    public async Task EnrollAsync(Guid userId, byte[] rawSecret, CancellationToken ct = default)
    {
        var encrypted = _cipher.Encrypt(rawSecret);

        // INSERT … ON CONFLICT lets re-enrollment overwrite cleanly without a separate delete.
        const string sql = @"
            INSERT INTO user_totp_secrets (user_id, secret_encrypted, enrolled_at)
            VALUES (@uid, @secret, now())
            ON CONFLICT (user_id) DO UPDATE
              SET secret_encrypted = EXCLUDED.secret_encrypted,
                  enrolled_at = EXCLUDED.enrolled_at,
                  last_used_at = NULL,
                  last_used_step = NULL";

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("uid", userId);
        cmd.Parameters.AddWithValue("secret", encrypted);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<bool> VerifyAsync(Guid userId, string code, CancellationToken ct = default)
    {
        var stored = await GetAsync(userId, ct);
        if (stored == null) return false;

        byte[] plain;
        try { plain = _cipher.Decrypt(stored.SecretEncrypted); }
        catch (Exception ex)
        {
            _logger.LogError(ex, "TOTP secret decryption failed for user {UserId} — wrong master key?", userId);
            return false;
        }

        var step = _totp.Verify(plain, code, stored.LastUsedStep, DateTimeOffset.UtcNow);
        Array.Clear(plain);
        if (!step.HasValue) return false;

        // Advance the replay counter.
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "UPDATE user_totp_secrets SET last_used_at = now(), last_used_step = @s WHERE user_id = @uid", conn);
        cmd.Parameters.AddWithValue("uid", userId);
        cmd.Parameters.AddWithValue("s", step.Value);
        await cmd.ExecuteNonQueryAsync(ct);
        return true;
    }

    public async Task ResetAsync(Guid userId, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("DELETE FROM user_totp_secrets WHERE user_id = @uid", conn);
        cmd.Parameters.AddWithValue("uid", userId);
        await cmd.ExecuteNonQueryAsync(ct);
    }
}
