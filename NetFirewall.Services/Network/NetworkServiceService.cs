using Microsoft.Extensions.Logging;
using NetFirewall.Models.Network;
using Npgsql;

namespace NetFirewall.Services.Network;

public sealed class NetworkServiceService : INetworkServiceService
{
    private readonly NpgsqlDataSource _ds;
    private readonly ILogger<NetworkServiceService> _logger;

    public NetworkServiceService(NpgsqlDataSource ds, ILogger<NetworkServiceService> logger)
    {
        _ds = ds;
        _logger = logger;
    }

    public async Task<IReadOnlyList<NetworkService>> GetAllAsync(bool includeMembers = false, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        var list = await ReadAsync(conn, "SELECT * FROM network_services ORDER BY category, name", ct);
        if (includeMembers) await LoadMembersAsync(conn, list, ct);
        return list;
    }

    public async Task<NetworkService?> GetByIdAsync(Guid id, bool includeMembers = false, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        var list = await ReadAsync(conn, "SELECT * FROM network_services WHERE id = @id", ct,
            cmd => cmd.Parameters.AddWithValue("id", id));
        var s = list.FirstOrDefault();
        if (s is not null && includeMembers) await LoadMembersAsync(conn, new[] { s }, ct);
        return s;
    }

    public async Task<NetworkService?> GetByNameAsync(string name, bool includeMembers = false, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        var list = await ReadAsync(conn, "SELECT * FROM network_services WHERE name = @n", ct,
            cmd => cmd.Parameters.AddWithValue("n", name));
        var s = list.FirstOrDefault();
        if (s is not null && includeMembers) await LoadMembersAsync(conn, new[] { s }, ct);
        return s;
    }

    public async Task<NetworkService> CreateAsync(NetworkService s, CancellationToken ct = default)
    {
        Validate(s);
        s.Id = Guid.NewGuid();
        s.CreatedAt = s.UpdatedAt = DateTime.UtcNow;

        await using var conn = await _ds.OpenConnectionAsync(ct);
        const string sql = @"
            INSERT INTO network_services (id, name, protocol, port_start, port_end, description,
                                          category, is_builtin, created_at, updated_at)
            VALUES (@id, @n, @proto, @ps, @pe, @desc, @cat, @bi, @ca, @ua)";
        await using var cmd = new NpgsqlCommand(sql, conn);
        Bind(cmd, s);
        await cmd.ExecuteNonQueryAsync(ct);

        _logger.LogInformation("Network service created: {Name} ({Proto}/{Port})", s.Name, s.Protocol, s.PortString);
        return s;
    }

    public async Task<NetworkService> UpdateAsync(NetworkService s, CancellationToken ct = default)
    {
        Validate(s);
        s.UpdatedAt = DateTime.UtcNow;

        await using var conn = await _ds.OpenConnectionAsync(ct);
        const string sql = @"
            UPDATE network_services SET
                name = @n, protocol = @proto, port_start = @ps, port_end = @pe,
                description = @desc, category = @cat, updated_at = @ua
            WHERE id = @id";
        await using var cmd = new NpgsqlCommand(sql, conn);
        Bind(cmd, s);
        await cmd.ExecuteNonQueryAsync(ct);
        return s;
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("DELETE FROM network_services WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        return await cmd.ExecuteNonQueryAsync(ct) > 0;
    }

    public async Task SetGroupMembersAsync(Guid parentId, IEnumerable<Guid> childIds, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        await using (var del = new NpgsqlCommand("DELETE FROM network_service_groups WHERE parent_id = @p", conn, tx))
        {
            del.Parameters.AddWithValue("p", parentId);
            await del.ExecuteNonQueryAsync(ct);
        }
        foreach (var c in childIds.Distinct().Where(c => c != parentId))
        {
            await using var ins = new NpgsqlCommand(
                "INSERT INTO network_service_groups (parent_id, child_id) VALUES (@p, @c)", conn, tx);
            ins.Parameters.AddWithValue("p", parentId);
            ins.Parameters.AddWithValue("c", c);
            await ins.ExecuteNonQueryAsync(ct);
        }
        await tx.CommitAsync(ct);
    }

    // ---------- internals ----------

    private static void Validate(NetworkService s)
    {
        if (string.IsNullOrWhiteSpace(s.Name))
            throw new ArgumentException("Service name is required.");
        if (!NetworkServiceProtocols.IsValid(s.Protocol))
            throw new ArgumentException($"Invalid protocol '{s.Protocol}'.");
        if (s.PortStart is < 0 or > 65535)
            throw new ArgumentException("port_start must be 0-65535.");
        if (s.PortEnd is { } pe && (pe < s.PortStart || pe > 65535))
            throw new ArgumentException("port_end must be ≥ port_start and ≤ 65535.");
    }

    private static void Bind(NpgsqlCommand cmd, NetworkService s)
    {
        cmd.Parameters.AddWithValue("id",   s.Id);
        cmd.Parameters.AddWithValue("n",    s.Name);
        cmd.Parameters.AddWithValue("proto", s.Protocol);
        cmd.Parameters.AddWithValue("ps",   s.PortStart);
        cmd.Parameters.AddWithValue("pe",   (object?)s.PortEnd ?? DBNull.Value);
        cmd.Parameters.AddWithValue("desc", (object?)s.Description ?? DBNull.Value);
        cmd.Parameters.AddWithValue("cat",  (object?)s.Category    ?? DBNull.Value);
        cmd.Parameters.AddWithValue("bi",   s.IsBuiltin);
        cmd.Parameters.AddWithValue("ca",   s.CreatedAt);
        cmd.Parameters.AddWithValue("ua",   s.UpdatedAt);
    }

    private static async Task<List<NetworkService>> ReadAsync(
        NpgsqlConnection conn, string sql, CancellationToken ct, Action<NpgsqlCommand>? bind = null)
    {
        await using var cmd = new NpgsqlCommand(sql, conn);
        bind?.Invoke(cmd);
        var list = new List<NetworkService>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            list.Add(new NetworkService
            {
                Id          = reader.GetGuid(reader.GetOrdinal("id")),
                Name        = reader.GetString(reader.GetOrdinal("name")),
                Protocol    = reader.GetString(reader.GetOrdinal("protocol")),
                PortStart   = reader.GetInt32(reader.GetOrdinal("port_start")),
                PortEnd     = reader.IsDBNull(reader.GetOrdinal("port_end")) ? null : reader.GetInt32(reader.GetOrdinal("port_end")),
                Description = reader.IsDBNull(reader.GetOrdinal("description")) ? null : reader.GetString(reader.GetOrdinal("description")),
                Category    = reader.IsDBNull(reader.GetOrdinal("category"))    ? null : reader.GetString(reader.GetOrdinal("category")),
                IsBuiltin   = reader.GetBoolean(reader.GetOrdinal("is_builtin")),
                CreatedAt   = reader.GetDateTime(reader.GetOrdinal("created_at")),
                UpdatedAt   = reader.GetDateTime(reader.GetOrdinal("updated_at"))
            });
        }
        return list;
    }

    private static async Task LoadMembersAsync(NpgsqlConnection conn, IReadOnlyList<NetworkService> parents, CancellationToken ct)
    {
        var ids = parents.Select(p => p.Id).ToArray();
        if (ids.Length == 0) return;

        const string sql = @"
            SELECT m.parent_id, c.*
              FROM network_service_groups m
              JOIN network_services c ON c.id = m.child_id
             WHERE m.parent_id = ANY(@ids)";
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("ids", ids);

        var byParent = parents.ToDictionary(p => p.Id, p => p);
        foreach (var p in parents) p.Members ??= new List<NetworkService>();

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var pid = reader.GetGuid(0);
            if (!byParent.TryGetValue(pid, out var parent)) continue;
            parent.Members!.Add(new NetworkService
            {
                Id          = reader.GetGuid(reader.GetOrdinal("id")),
                Name        = reader.GetString(reader.GetOrdinal("name")),
                Protocol    = reader.GetString(reader.GetOrdinal("protocol")),
                PortStart   = reader.GetInt32(reader.GetOrdinal("port_start")),
                PortEnd     = reader.IsDBNull(reader.GetOrdinal("port_end")) ? null : reader.GetInt32(reader.GetOrdinal("port_end")),
                Description = reader.IsDBNull(reader.GetOrdinal("description")) ? null : reader.GetString(reader.GetOrdinal("description")),
                Category    = reader.IsDBNull(reader.GetOrdinal("category"))    ? null : reader.GetString(reader.GetOrdinal("category")),
                IsBuiltin   = reader.GetBoolean(reader.GetOrdinal("is_builtin")),
                CreatedAt   = reader.GetDateTime(reader.GetOrdinal("created_at")),
                UpdatedAt   = reader.GetDateTime(reader.GetOrdinal("updated_at")),
            });
        }
    }
}
