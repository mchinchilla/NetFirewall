using Microsoft.Extensions.Logging;
using NetFirewall.Models.Network;
using Npgsql;

namespace NetFirewall.Services.Network;

public sealed class NetworkObjectService : INetworkObjectService
{
    private readonly NpgsqlDataSource _ds;
    private readonly ILogger<NetworkObjectService> _logger;

    public NetworkObjectService(NpgsqlDataSource ds, ILogger<NetworkObjectService> logger)
    {
        _ds = ds;
        _logger = logger;
    }

    public async Task<IReadOnlyList<NetworkObject>> GetAllAsync(bool includeMembers = false, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        var list = await ReadObjectsAsync(conn, "SELECT * FROM network_objects ORDER BY type, name", ct);
        if (includeMembers) await LoadMembersAsync(conn, list, ct);
        return list;
    }

    public async Task<NetworkObject?> GetByIdAsync(Guid id, bool includeMembers = false, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        var list = await ReadObjectsAsync(conn,
            "SELECT * FROM network_objects WHERE id = @id", ct,
            cmd => cmd.Parameters.AddWithValue("id", id));
        var obj = list.FirstOrDefault();
        if (obj is not null && includeMembers) await LoadMembersAsync(conn, new[] { obj }, ct);
        return obj;
    }

    public async Task<NetworkObject?> GetByNameAsync(string name, bool includeMembers = false, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        var list = await ReadObjectsAsync(conn,
            "SELECT * FROM network_objects WHERE name = @n", ct,
            cmd => cmd.Parameters.AddWithValue("n", name));
        var obj = list.FirstOrDefault();
        if (obj is not null && includeMembers) await LoadMembersAsync(conn, new[] { obj }, ct);
        return obj;
    }

    public async Task<NetworkObject> CreateAsync(NetworkObject obj, CancellationToken ct = default)
    {
        Validate(obj);
        obj.Id = Guid.NewGuid();
        obj.CreatedAt = obj.UpdatedAt = DateTime.UtcNow;

        await using var conn = await _ds.OpenConnectionAsync(ct);
        const string sql = @"
            INSERT INTO network_objects (id, name, type, value, description, created_at, updated_at)
            VALUES (@id, @n, @t, @v, @d, @ca, @ua)";
        await using var cmd = new NpgsqlCommand(sql, conn);
        BindObject(cmd, obj);
        await cmd.ExecuteNonQueryAsync(ct);

        _logger.LogInformation("Network object created: {Name} ({Type})", obj.Name, obj.Type);
        return obj;
    }

    public async Task<NetworkObject> UpdateAsync(NetworkObject obj, CancellationToken ct = default)
    {
        Validate(obj);
        obj.UpdatedAt = DateTime.UtcNow;

        await using var conn = await _ds.OpenConnectionAsync(ct);
        const string sql = @"
            UPDATE network_objects
               SET name = @n, type = @t, value = @v, description = @d, updated_at = @ua
             WHERE id = @id";
        await using var cmd = new NpgsqlCommand(sql, conn);
        BindObject(cmd, obj);
        await cmd.ExecuteNonQueryAsync(ct);
        return obj;
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("DELETE FROM network_objects WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        return await cmd.ExecuteNonQueryAsync(ct) > 0;
    }

    public async Task<NetworkObjectUsage> FindUsagesAsync(string objectName, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);

        async Task<List<UsageEntry>> ScanArrayCols(string table, string[] cols)
        {
            var entries = new List<UsageEntry>();
            foreach (var col in cols)
            {
                var sql = $"SELECT id, COALESCE(description, '(no description)') AS d, '{col}' AS field " +
                          $"FROM {table} WHERE @n = ANY({col})";
                await using var cmd = new NpgsqlCommand(sql, conn);
                cmd.Parameters.AddWithValue("n", objectName);
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct))
                {
                    entries.Add(new UsageEntry(
                        reader.GetGuid(0),
                        reader.GetString(1),
                        reader.GetString(2)));
                }
            }
            return entries;
        }

        async Task<List<UsageEntry>> ScanScalarCol(string table, string col)
        {
            // Cast the column to text so cidr/inet columns compare cleanly against
            // an object name string. Names that aren't valid CIDRs won't match.
            var sql = $"SELECT id, COALESCE(description, '(no description)') AS d, '{col}' AS field " +
                      $"FROM {table} WHERE {col}::text = @n";
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("n", objectName);
            var entries = new List<UsageEntry>();
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                entries.Add(new UsageEntry(reader.GetGuid(0), reader.GetString(1), reader.GetString(2)));
            }
            return entries;
        }

        async Task<List<UsageEntry>> FindParentGroups()
        {
            const string sql = @"
                SELECT p.id, p.name
                  FROM network_object_members m
                  JOIN network_objects p ON p.id = m.parent_id
                  JOIN network_objects c ON c.id = m.child_id
                 WHERE c.name = @n";
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("n", objectName);
            var entries = new List<UsageEntry>();
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
                entries.Add(new UsageEntry(reader.GetGuid(0), reader.GetString(1), "members"));
            return entries;
        }

        // Tables may not exist yet (partial install). Catch undefined_table per scan.
        var filter  = await Safe(() => ScanArrayCols("fw_filter_rules",  new[] { "source_addresses", "destination_addresses" }));
        var pf      = await Safe(() => ScanArrayCols("fw_port_forwards", new[] { "source_addresses" }));
        var mangle  = await Safe(() => ScanArrayCols("fw_mangle_rules",  new[] { "source_addresses", "destination_addresses" }));
        var nat     = await Safe(() => ScanScalarCol("fw_nat_rules",     "source_network"));
        var parents = await Safe(FindParentGroups);

        return new NetworkObjectUsage(filter, pf, nat, mangle, parents);
    }

    private static async Task<List<UsageEntry>> Safe(Func<Task<List<UsageEntry>>> fn)
    {
        try { return await fn(); }
        catch (PostgresException ex) when (ex.SqlState == "42P01") // undefined_table
        {
            return new List<UsageEntry>();
        }
    }

    public async Task SetGroupMembersAsync(Guid parentId, IEnumerable<Guid> childIds, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);

        // Verify parent IS a group — otherwise members make no sense.
        await using (var check = new NpgsqlCommand("SELECT type FROM network_objects WHERE id = @id", conn, tx))
        {
            check.Parameters.AddWithValue("id", parentId);
            var t = (string?)await check.ExecuteScalarAsync(ct);
            if (t != NetworkObjectTypes.Group)
                throw new InvalidOperationException("Members can only be set on a group object.");
        }

        await using (var del = new NpgsqlCommand("DELETE FROM network_object_members WHERE parent_id = @p", conn, tx))
        {
            del.Parameters.AddWithValue("p", parentId);
            await del.ExecuteNonQueryAsync(ct);
        }

        foreach (var child in childIds.Distinct().Where(c => c != parentId))
        {
            await using var ins = new NpgsqlCommand(
                "INSERT INTO network_object_members (parent_id, child_id) VALUES (@p, @c)", conn, tx);
            ins.Parameters.AddWithValue("p", parentId);
            ins.Parameters.AddWithValue("c", child);
            await ins.ExecuteNonQueryAsync(ct);
        }

        await tx.CommitAsync(ct);
    }

    // ----- internals -----

    private static void Validate(NetworkObject obj)
    {
        if (string.IsNullOrWhiteSpace(obj.Name))
            throw new ArgumentException("Name is required.");
        if (!NetworkObjectTypes.IsValid(obj.Type))
            throw new ArgumentException($"Invalid type '{obj.Type}'. Must be one of: {string.Join(", ", NetworkObjectTypes.All)}.");
        if (obj.Type != NetworkObjectTypes.Group && string.IsNullOrWhiteSpace(obj.Value))
            throw new ArgumentException($"Value is required for {obj.Type} objects.");
    }

    private static void BindObject(NpgsqlCommand cmd, NetworkObject obj)
    {
        cmd.Parameters.AddWithValue("id", obj.Id);
        cmd.Parameters.AddWithValue("n",  obj.Name);
        cmd.Parameters.AddWithValue("t",  obj.Type);
        cmd.Parameters.AddWithValue("v",  obj.Value ?? string.Empty);
        cmd.Parameters.AddWithValue("d",  (object?)obj.Description ?? DBNull.Value);
        cmd.Parameters.AddWithValue("ca", obj.CreatedAt);
        cmd.Parameters.AddWithValue("ua", obj.UpdatedAt);
    }

    private static async Task<List<NetworkObject>> ReadObjectsAsync(
        NpgsqlConnection conn, string sql, CancellationToken ct, Action<NpgsqlCommand>? bind = null)
    {
        await using var cmd = new NpgsqlCommand(sql, conn);
        bind?.Invoke(cmd);
        var list = new List<NetworkObject>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            list.Add(new NetworkObject
            {
                Id          = reader.GetGuid(reader.GetOrdinal("id")),
                Name        = reader.GetString(reader.GetOrdinal("name")),
                Type        = reader.GetString(reader.GetOrdinal("type")),
                Value       = reader.GetString(reader.GetOrdinal("value")),
                Description = reader.IsDBNull(reader.GetOrdinal("description")) ? null : reader.GetString(reader.GetOrdinal("description")),
                CreatedAt   = reader.GetDateTime(reader.GetOrdinal("created_at")),
                UpdatedAt   = reader.GetDateTime(reader.GetOrdinal("updated_at")),
            });
        }
        return list;
    }

    private static async Task LoadMembersAsync(NpgsqlConnection conn, IReadOnlyList<NetworkObject> parents, CancellationToken ct)
    {
        var ids = parents.Where(p => p.Type == NetworkObjectTypes.Group).Select(p => p.Id).ToArray();
        if (ids.Length == 0) return;

        const string sql = @"
            SELECT m.parent_id, c.*
              FROM network_object_members m
              JOIN network_objects c ON c.id = m.child_id
             WHERE m.parent_id = ANY(@ids)";
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("ids", ids);

        var byParent = parents.ToDictionary(p => p.Id, p => p);
        foreach (var p in parents) p.Members ??= new List<NetworkObject>();

        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var parentId = reader.GetGuid(0);
            if (!byParent.TryGetValue(parentId, out var parent)) continue;

            parent.Members!.Add(new NetworkObject
            {
                Id          = reader.GetGuid(reader.GetOrdinal("id")),
                Name        = reader.GetString(reader.GetOrdinal("name")),
                Type        = reader.GetString(reader.GetOrdinal("type")),
                Value       = reader.GetString(reader.GetOrdinal("value")),
                Description = reader.IsDBNull(reader.GetOrdinal("description")) ? null : reader.GetString(reader.GetOrdinal("description")),
                CreatedAt   = reader.GetDateTime(reader.GetOrdinal("created_at")),
                UpdatedAt   = reader.GetDateTime(reader.GetOrdinal("updated_at")),
            });
        }
    }
}
