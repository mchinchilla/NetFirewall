using Microsoft.Extensions.Logging;
using NetFirewall.Models.Vpn;
using Npgsql;

namespace NetFirewall.Services.Vpn;

public sealed class WireGuardService : IWireGuardService
{
    private readonly NpgsqlDataSource _ds;
    private readonly ILogger<WireGuardService> _logger;

    public WireGuardService(NpgsqlDataSource ds, ILogger<WireGuardService> logger)
    {
        _ds = ds;
        _logger = logger;
    }

    public async Task<WgServer?> GetServerAsync(CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "SELECT * FROM wg_servers ORDER BY created_at LIMIT 1", conn);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? ReadServer(reader) : null;
    }

    public async Task<WgServer> SaveServerAsync(WgServer server, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        var isNew = server.Id == Guid.Empty;
        if (isNew)
        {
            server.Id = Guid.NewGuid();
            server.CreatedAt = DateTime.UtcNow;
        }
        server.UpdatedAt = DateTime.UtcNow;

        const string sql = @"
            INSERT INTO wg_servers
                (id, name, mode, private_key, public_key, listen_port, address_cidr,
                 dns, mtu, table_off, post_up, post_down, enabled, created_at, updated_at)
            VALUES
                (@id, @name, @mode, @priv, @pub, @port, @addr,
                 @dns, @mtu, @tableOff, @up, @down, @enabled, @created, @updated)
            ON CONFLICT (id) DO UPDATE SET
                name = EXCLUDED.name,
                mode = EXCLUDED.mode,
                private_key = EXCLUDED.private_key,
                public_key = EXCLUDED.public_key,
                listen_port = EXCLUDED.listen_port,
                address_cidr = EXCLUDED.address_cidr,
                dns = EXCLUDED.dns,
                mtu = EXCLUDED.mtu,
                table_off = EXCLUDED.table_off,
                post_up = EXCLUDED.post_up,
                post_down = EXCLUDED.post_down,
                enabled = EXCLUDED.enabled,
                updated_at = EXCLUDED.updated_at";
        await using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", server.Id);
        cmd.Parameters.AddWithValue("name", server.Name);
        cmd.Parameters.AddWithValue("mode", server.Mode);
        cmd.Parameters.AddWithValue("priv", server.PrivateKey);
        cmd.Parameters.AddWithValue("pub", server.PublicKey);
        cmd.Parameters.AddWithValue("port", server.ListenPort);
        cmd.Parameters.AddWithValue("addr", server.AddressCidr);
        cmd.Parameters.AddWithValue("dns",   (object?)server.Dns ?? DBNull.Value);
        cmd.Parameters.AddWithValue("mtu",   (object?)server.Mtu ?? DBNull.Value);
        cmd.Parameters.AddWithValue("tableOff", server.TableOff);
        cmd.Parameters.AddWithValue("up",   (object?)server.PostUp   ?? DBNull.Value);
        cmd.Parameters.AddWithValue("down", (object?)server.PostDown ?? DBNull.Value);
        cmd.Parameters.AddWithValue("enabled", server.Enabled);
        cmd.Parameters.AddWithValue("created", server.CreatedAt);
        cmd.Parameters.AddWithValue("updated", server.UpdatedAt);
        await cmd.ExecuteNonQueryAsync(ct);

        _logger.LogInformation("WireGuard server saved ({New}) {Name} {Addr}:{Port}",
            isNew ? "new" : "update", server.Name, server.AddressCidr, server.ListenPort);
        return server;
    }

    public async Task<bool> DeleteServerAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("DELETE FROM wg_servers WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        return await cmd.ExecuteNonQueryAsync(ct) > 0;
    }

    public async Task<IReadOnlyList<WgPeer>> GetPeersAsync(Guid serverId, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "SELECT * FROM wg_peers WHERE server_id = @s ORDER BY name", conn);
        cmd.Parameters.AddWithValue("s", serverId);
        var list = new List<WgPeer>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) list.Add(ReadPeer(reader));
        return list;
    }

    public async Task<WgPeer?> GetPeerByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("SELECT * FROM wg_peers WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? ReadPeer(reader) : null;
    }

    public async Task<WgPeer> CreatePeerAsync(WgPeer peer, CancellationToken ct = default)
    {
        peer.Id = Guid.NewGuid();
        peer.CreatedAt = DateTime.UtcNow;

        await using var conn = await _ds.OpenConnectionAsync(ct);
        const string sql = @"
            INSERT INTO wg_peers
                (id, server_id, name, public_key, preshared_key, allowed_ips,
                 persistent_keepalive, endpoint, role, route_mode, allowed_subnets,
                 description, enabled, created_at)
            VALUES
                (@id, @sid, @name, @pub, @psk, @ips, @ka, @endpoint, @role, @rmode, @subnets,
                 @desc, @enabled, @created)";
        await using var cmd = new NpgsqlCommand(sql, conn);
        BindPeerParams(cmd, peer);
        cmd.Parameters.AddWithValue("created", peer.CreatedAt);
        await cmd.ExecuteNonQueryAsync(ct);

        _logger.LogInformation("WireGuard peer created: {Name} ({Pub})", peer.Name, peer.PublicKey[..8]);
        return peer;
    }

    public async Task<WgPeer> UpdatePeerAsync(WgPeer peer, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        const string sql = @"
            UPDATE wg_peers SET
                name = @name, public_key = @pub, preshared_key = @psk,
                allowed_ips = @ips, persistent_keepalive = @ka,
                endpoint = @endpoint, role = @role, route_mode = @rmode,
                allowed_subnets = @subnets,
                description = @desc, enabled = @enabled
            WHERE id = @id";
        await using var cmd = new NpgsqlCommand(sql, conn);
        BindPeerParams(cmd, peer);
        await cmd.ExecuteNonQueryAsync(ct);
        return peer;
    }

    public async Task<bool> DeletePeerAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("DELETE FROM wg_peers WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        return await cmd.ExecuteNonQueryAsync(ct) > 0;
    }

    // ----- helpers -----

    private static void BindPeerParams(NpgsqlCommand cmd, WgPeer p)
    {
        cmd.Parameters.AddWithValue("id", p.Id);
        cmd.Parameters.AddWithValue("sid", p.ServerId);
        cmd.Parameters.AddWithValue("name", p.Name);
        cmd.Parameters.AddWithValue("pub", p.PublicKey);
        cmd.Parameters.AddWithValue("psk", (object?)p.PresharedKey ?? DBNull.Value);
        cmd.Parameters.AddWithValue("ips", p.AllowedIps);
        cmd.Parameters.AddWithValue("ka", (object?)p.PersistentKeepalive ?? DBNull.Value);
        cmd.Parameters.AddWithValue("endpoint", (object?)p.Endpoint ?? DBNull.Value);
        cmd.Parameters.AddWithValue("role", string.IsNullOrEmpty(p.Role) ? "client" : p.Role);
        cmd.Parameters.AddWithValue("rmode", string.IsNullOrEmpty(p.RouteMode) ? "full" : p.RouteMode);
        cmd.Parameters.AddWithValue("subnets", p.AllowedSubnets ?? Array.Empty<string>());
        cmd.Parameters.AddWithValue("desc", (object?)p.Description ?? DBNull.Value);
        cmd.Parameters.AddWithValue("enabled", p.Enabled);
    }

    private static WgServer ReadServer(NpgsqlDataReader r) => new()
    {
        Id          = r.GetGuid(r.GetOrdinal("id")),
        Name        = r.GetString(r.GetOrdinal("name")),
        Mode        = r.GetString(r.GetOrdinal("mode")),
        PrivateKey  = r.GetString(r.GetOrdinal("private_key")),
        PublicKey   = r.GetString(r.GetOrdinal("public_key")),
        ListenPort  = r.GetInt32(r.GetOrdinal("listen_port")),
        AddressCidr = r.GetString(r.GetOrdinal("address_cidr")),
        Dns         = r.IsDBNull(r.GetOrdinal("dns"))       ? null : r.GetString(r.GetOrdinal("dns")),
        Mtu         = r.IsDBNull(r.GetOrdinal("mtu"))       ? null : r.GetInt32(r.GetOrdinal("mtu")),
        TableOff    = r.GetBoolean(r.GetOrdinal("table_off")),
        PostUp      = r.IsDBNull(r.GetOrdinal("post_up"))   ? null : r.GetString(r.GetOrdinal("post_up")),
        PostDown    = r.IsDBNull(r.GetOrdinal("post_down")) ? null : r.GetString(r.GetOrdinal("post_down")),
        Enabled     = r.GetBoolean(r.GetOrdinal("enabled")),
        CreatedAt   = r.GetDateTime(r.GetOrdinal("created_at")),
        UpdatedAt   = r.GetDateTime(r.GetOrdinal("updated_at"))
    };

    private static WgPeer ReadPeer(NpgsqlDataReader r) => new()
    {
        Id                  = r.GetGuid(r.GetOrdinal("id")),
        ServerId            = r.GetGuid(r.GetOrdinal("server_id")),
        Name                = r.GetString(r.GetOrdinal("name")),
        PublicKey           = r.GetString(r.GetOrdinal("public_key")),
        PresharedKey        = r.IsDBNull(r.GetOrdinal("preshared_key")) ? null : r.GetString(r.GetOrdinal("preshared_key")),
        AllowedIps          = r.IsDBNull(r.GetOrdinal("allowed_ips")) ? Array.Empty<string>() : (string[])r["allowed_ips"],
        PersistentKeepalive = r.IsDBNull(r.GetOrdinal("persistent_keepalive")) ? null : r.GetInt32(r.GetOrdinal("persistent_keepalive")),
        Endpoint            = r.IsDBNull(r.GetOrdinal("endpoint")) ? null : r.GetString(r.GetOrdinal("endpoint")),
        Role                = r.IsDBNull(r.GetOrdinal("role")) ? "client" : r.GetString(r.GetOrdinal("role")),
        RouteMode           = r.IsDBNull(r.GetOrdinal("route_mode")) ? "full" : r.GetString(r.GetOrdinal("route_mode")),
        AllowedSubnets      = r.IsDBNull(r.GetOrdinal("allowed_subnets")) ? Array.Empty<string>() : (string[])r["allowed_subnets"],
        Description         = r.IsDBNull(r.GetOrdinal("description")) ? null : r.GetString(r.GetOrdinal("description")),
        Enabled             = r.GetBoolean(r.GetOrdinal("enabled")),
        CreatedAt           = r.GetDateTime(r.GetOrdinal("created_at"))
    };
}
