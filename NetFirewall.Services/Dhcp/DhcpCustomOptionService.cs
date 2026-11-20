using Microsoft.Extensions.Logging;
using NetFirewall.Models;
using NetFirewall.Models.Dhcp;
using Npgsql;

namespace NetFirewall.Services.Dhcp;

/// <summary>A custom option as listed in the UI, with its scope resolved to a name.</summary>
public sealed record DhcpCustomOptionRow(
    Guid Id, string ScopeType, Guid? ScopeId, string ScopeLabel,
    short Code, string? Name, string? Format, string ValueText);

/// <summary>What the form posts (validated again here).</summary>
public sealed record DhcpCustomOptionInput(
    Guid? Id, string ScopeType, Guid? ScopeId, int Code, string? Name, string Format, string Value);

/// <summary>CRUD over dhcp_custom_options. The DHCP server reads them from its cache (refreshed by NOTIFY).</summary>
public interface IDhcpCustomOptionService
{
    Task<IReadOnlyList<DhcpCustomOptionRow>> ListAsync(CancellationToken ct = default);
    Task<DhcpCustomOptionRow?> GetAsync(Guid id, CancellationToken ct = default);
    /// <summary>Insert, or update the existing value of the same code in the same scope.</summary>
    Task<ServiceResponse<DhcpCustomOptionRow>> SaveAsync(DhcpCustomOptionInput input, CancellationToken ct = default);
    Task<bool> DeleteAsync(Guid id, CancellationToken ct = default);
    /// <summary>Targets for a scope: subnets, classes or reservations (id, label).</summary>
    Task<IReadOnlyList<(Guid Id, string Label)>> ScopeTargetsAsync(string scopeType, CancellationToken ct = default);
}

public sealed class DhcpCustomOptionService(
    NpgsqlDataSource ds,
    IDhcpCacheNotifier notifier,
    ILogger<DhcpCustomOptionService> logger) : IDhcpCustomOptionService
{
    private const string SelectRows = """
        SELECT o.id, o.scope_type, o.scope_id, o.option_code, o.option_name, o.option_format, o.option_value,
               CASE o.scope_type
                   WHEN 'global' THEN 'All clients'
                   WHEN 'subnet' THEN 'Subnet ' || COALESCE(s.name, '(deleted)')
                   WHEN 'class'  THEN 'Class '  || COALESCE(c.name, '(deleted)')
                   WHEN 'host'   THEN 'Device ' || COALESCE(lower(r.mac_address::text) || ' (' || host(r.reserved_ip) || ')', '(deleted)')
               END
        FROM dhcp_custom_options o
        LEFT JOIN dhcp_subnets s           ON o.scope_type = 'subnet' AND s.id = o.scope_id
        LEFT JOIN dhcp_classes c           ON o.scope_type = 'class'  AND c.id = o.scope_id
        LEFT JOIN dhcp_mac_reservations r  ON o.scope_type = 'host'   AND r.id = o.scope_id
        """;

    public async Task<IReadOnlyList<DhcpCustomOptionRow>> ListAsync(CancellationToken ct = default)
    {
        await using var conn = await ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(SelectRows + " ORDER BY o.scope_type, o.option_code", conn);
        return await ReadAsync(cmd, ct);
    }

    public async Task<DhcpCustomOptionRow?> GetAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(SelectRows + " WHERE o.id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        return (await ReadAsync(cmd, ct)).FirstOrDefault();
    }

    public async Task<ServiceResponse<DhcpCustomOptionRow>> SaveAsync(DhcpCustomOptionInput input, CancellationToken ct = default)
    {
        if (!DhcpOptionScopes.All.Contains(input.ScopeType))
            return ServiceResponse<DhcpCustomOptionRow>.Fail("Pick who the option is for.");
        var scopeId = input.ScopeType == DhcpOptionScopes.Global ? null : input.ScopeId;
        if (input.ScopeType != DhcpOptionScopes.Global && scopeId is null)
            return ServiceResponse<DhcpCustomOptionRow>.Fail($"Pick the {input.ScopeType} the option applies to.");
        if (!DhcpOptionFormats.All.Contains(input.Format))
            return ServiceResponse<DhcpCustomOptionRow>.Fail("Pick the value format.");
        if (!DhcpOptionEncoder.TryEncode(input.Code, input.Format, input.Value, out var bytes, out var error))
            return ServiceResponse<DhcpCustomOptionRow>.Fail(error!);

        await using var conn = await ds.OpenConnectionAsync(ct);
        if (scopeId is { } sid && !await ScopeExistsAsync(conn, input.ScopeType, sid, ct))
            return ServiceResponse<DhcpCustomOptionRow>.Fail("That subnet, class or device no longer exists.");

        Guid id;
        await using (var cmd = new NpgsqlCommand("""
            INSERT INTO dhcp_custom_options (id, scope_type, scope_id, option_code, option_name, option_value, option_format)
            VALUES (COALESCE(@id, uuid_generate_v4()), @scope, @scopeId, @code, @name, @value, @format)
            ON CONFLICT (scope_type, COALESCE(scope_id, '00000000-0000-0000-0000-000000000000'::uuid), option_code)
            DO UPDATE SET option_name = EXCLUDED.option_name, option_value = EXCLUDED.option_value,
                          option_format = EXCLUDED.option_format
            RETURNING id
            """, conn))
        {
            cmd.Parameters.AddWithValue("id", (object?)input.Id ?? DBNull.Value).NpgsqlDbType = NpgsqlTypes.NpgsqlDbType.Uuid;
            cmd.Parameters.AddWithValue("scope", input.ScopeType);
            cmd.Parameters.AddWithValue("scopeId", (object?)scopeId ?? DBNull.Value).NpgsqlDbType = NpgsqlTypes.NpgsqlDbType.Uuid;
            cmd.Parameters.AddWithValue("code", (short)input.Code);
            cmd.Parameters.AddWithValue("name", string.IsNullOrWhiteSpace(input.Name) ? DBNull.Value : input.Name.Trim());
            cmd.Parameters.AddWithValue("value", bytes);
            cmd.Parameters.AddWithValue("format", input.Format);
            id = (Guid)(await cmd.ExecuteScalarAsync(ct))!;
        }

        // An edit that moved the option to another scope/code leaves the old row behind: remove it.
        if (input.Id is { } edited && edited != id)
        {
            await using var del = new NpgsqlCommand("DELETE FROM dhcp_custom_options WHERE id = @id", conn);
            del.Parameters.AddWithValue("id", edited);
            await del.ExecuteNonQueryAsync(ct);
        }

        await notifier.NotifySubnetChangedAsync($"option.changed:{id}", ct);
        logger.LogInformation("DHCP custom option {Code} saved for {Scope} {ScopeId}", input.Code, input.ScopeType, scopeId);
        var row = await GetAsync(id, ct);
        return ServiceResponse<DhcpCustomOptionRow>.Ok(row!, $"Option {input.Code} saved — clients get it at their next renewal.");
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("DELETE FROM dhcp_custom_options WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        var deleted = await cmd.ExecuteNonQueryAsync(ct) > 0;
        if (deleted) await notifier.NotifySubnetChangedAsync($"option.deleted:{id}", ct);
        return deleted;
    }

    public async Task<IReadOnlyList<(Guid Id, string Label)>> ScopeTargetsAsync(string scopeType, CancellationToken ct = default)
    {
        var sql = scopeType switch
        {
            DhcpOptionScopes.Subnet => "SELECT id, name || ' (' || network::text || ')' FROM dhcp_subnets ORDER BY name",
            DhcpOptionScopes.Class => "SELECT id, name FROM dhcp_classes ORDER BY priority, name",
            DhcpOptionScopes.Host => "SELECT id, lower(mac_address::text) || ' → ' || host(reserved_ip) || COALESCE(' · ' || description, '') FROM dhcp_mac_reservations ORDER BY reserved_ip",
            _ => null,
        };
        if (sql is null) return [];
        await using var conn = await ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(sql, conn);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        var list = new List<(Guid, string)>();
        while (await r.ReadAsync(ct)) list.Add((r.GetGuid(0), r.GetString(1)));
        return list;
    }

    private static async Task<bool> ScopeExistsAsync(NpgsqlConnection conn, string scopeType, Guid id, CancellationToken ct)
    {
        var table = scopeType switch
        {
            DhcpOptionScopes.Subnet => "dhcp_subnets",
            DhcpOptionScopes.Class => "dhcp_classes",
            DhcpOptionScopes.Host => "dhcp_mac_reservations",
            _ => null,
        };
        if (table is null) return false;
        await using var cmd = new NpgsqlCommand($"SELECT EXISTS (SELECT 1 FROM {table} WHERE id = @id)", conn);
        cmd.Parameters.AddWithValue("id", id);
        return (bool)(await cmd.ExecuteScalarAsync(ct))!;
    }

    private static async Task<IReadOnlyList<DhcpCustomOptionRow>> ReadAsync(NpgsqlCommand cmd, CancellationToken ct)
    {
        var list = new List<DhcpCustomOptionRow>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            var format = r.IsDBNull(5) ? null : r.GetString(5);
            list.Add(new DhcpCustomOptionRow(
                r.GetGuid(0), r.GetString(1), r.IsDBNull(2) ? null : r.GetGuid(2), r.GetString(7),
                r.GetInt16(3), r.IsDBNull(4) ? null : r.GetString(4), format,
                DhcpOptionEncoder.Decode(format, (byte[])r[6])));
        }
        return list;
    }
}
