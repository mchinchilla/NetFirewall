using Microsoft.Extensions.Logging;
using Npgsql;

namespace NetFirewall.Services.Auth;

public sealed class RecoveryCodeService : IRecoveryCodeService
{
    private readonly NpgsqlDataSource _dataSource;
    private readonly IRecoveryCodeGenerator _generator;
    private readonly IPasswordHasher _hasher;          // Reusing Argon2 — same threat model: brute-force resistance
    private readonly ILogger<RecoveryCodeService> _logger;

    public RecoveryCodeService(
        NpgsqlDataSource dataSource,
        IRecoveryCodeGenerator generator,
        IPasswordHasher hasher,
        ILogger<RecoveryCodeService> logger)
    {
        _dataSource = dataSource;
        _generator = generator;
        _hasher = hasher;
        _logger = logger;
    }

    public async Task<IReadOnlyList<string>> RegenerateAsync(Guid userId, int count = 10, CancellationToken ct = default)
    {
        var codes = _generator.Generate(count);
        var hashes = new string[codes.Count];
        for (var i = 0; i < codes.Count; i++)
            hashes[i] = await _hasher.HashAsync(codes[i], ct);

        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);

        // Wipe any prior unused codes — re-generation invalidates the old set.
        await using (var del = new NpgsqlCommand(
            "DELETE FROM user_recovery_codes WHERE user_id = @uid AND used_at IS NULL", conn, tx))
        {
            del.Parameters.AddWithValue("uid", userId);
            await del.ExecuteNonQueryAsync(ct);
        }

        const string ins = "INSERT INTO user_recovery_codes (user_id, code_hash) VALUES (@uid, @h)";
        for (var i = 0; i < hashes.Length; i++)
        {
            await using var cmd = new NpgsqlCommand(ins, conn, tx);
            cmd.Parameters.AddWithValue("uid", userId);
            cmd.Parameters.AddWithValue("h", hashes[i]);
            await cmd.ExecuteNonQueryAsync(ct);
        }

        await tx.CommitAsync(ct);
        _logger.LogInformation("Issued {Count} recovery codes for user {UserId}", codes.Count, userId);
        return codes;
    }

    public async Task<int> CountUnusedAsync(Guid userId, CancellationToken ct = default)
    {
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "SELECT COUNT(*) FROM user_recovery_codes WHERE user_id = @uid AND used_at IS NULL", conn);
        cmd.Parameters.AddWithValue("uid", userId);
        return Convert.ToInt32(await cmd.ExecuteScalarAsync(ct));
    }

    public async Task<bool> VerifyAndConsumeAsync(Guid userId, string code, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(code)) return false;

        // Argon2 verification is expensive — fetch all unused hashes for this user
        // (typically ≤10) and walk them. This is safe because the user is already
        // identified; we're only checking which of their own codes matches.
        await using var conn = await _dataSource.OpenConnectionAsync(ct);
        await using var fetch = new NpgsqlCommand(
            "SELECT id, code_hash FROM user_recovery_codes WHERE user_id = @uid AND used_at IS NULL", conn);
        fetch.Parameters.AddWithValue("uid", userId);

        var candidates = new List<(Guid Id, string Hash)>();
        await using (var reader = await fetch.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
                candidates.Add((reader.GetGuid(0), reader.GetString(1)));
        }

        foreach (var (id, hash) in candidates)
        {
            var v = await _hasher.VerifyAsync(code, hash, ct);
            if (!v.Matches) continue;

            // Single-use — stamp it consumed.
            await using var consume = new NpgsqlCommand(
                "UPDATE user_recovery_codes SET used_at = now() WHERE id = @id AND used_at IS NULL", conn);
            consume.Parameters.AddWithValue("id", id);
            var n = await consume.ExecuteNonQueryAsync(ct);
            if (n == 0) return false; // race: another caller consumed it first
            _logger.LogInformation("Recovery code consumed for user {UserId}", userId);
            return true;
        }
        return false;
    }
}
