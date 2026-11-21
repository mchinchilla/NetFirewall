using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NetFirewall.Models;
using NetFirewall.Models.Dhcp;
using Npgsql;

namespace NetFirewall.Services.Dhcp;

/// <inheritdoc />
public sealed class DhcpAccessControlService(
    NpgsqlDataSource dataSource,
    IDhcpCacheNotifier notifier,
    ILogger<DhcpAccessControlService> logger) : IDhcpAccessControlService
{
    // ---------------- MAC block list ----------------

    public async Task<IReadOnlyList<DhcpBlockedMac>> GetBlockedMacsAsync(CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "SELECT id, mac_address, reason, created_at FROM dhcp_mac_blocklist ORDER BY created_at DESC", conn);
        return await ReadBlockedAsync(cmd, ct);
    }

    public async Task<DhcpBlockedMac?> GetBlockedMacAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "SELECT id, mac_address, reason, created_at FROM dhcp_mac_blocklist WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        return (await ReadBlockedAsync(cmd, ct)).FirstOrDefault();
    }

    public async Task<ServiceResponse<DhcpBlockedMac>> SaveBlockedMacAsync(DhcpBlockedMac entry, CancellationToken ct = default)
    {
        var bytes = entry.MacAddress.GetAddressBytes();
        if (bytes.Length != 6 || bytes.All(b => b == 0) || bytes.All(b => b == 0xFF))
            return ServiceResponse<DhcpBlockedMac>.Fail("Enter the device's MAC address (not all zeros or broadcast).");
        if (entry.Reason is { Length: > 255 })
            return ServiceResponse<DhcpBlockedMac>.Fail("Reason is at most 255 characters.");
        entry.Reason = string.IsNullOrWhiteSpace(entry.Reason) ? null : entry.Reason.Trim();

        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);
        try
        {
            var creating = entry.Id == Guid.Empty;
            await using (var cmd = new NpgsqlCommand(creating
                ? "INSERT INTO dhcp_mac_blocklist (mac_address, reason) VALUES (@mac, @reason) RETURNING id, created_at"
                : "UPDATE dhcp_mac_blocklist SET mac_address = @mac, reason = @reason WHERE id = @id RETURNING id, created_at", conn, tx))
            {
                cmd.Parameters.AddWithValue("mac", entry.MacAddress);
                cmd.Parameters.AddWithValue("reason", (object?)entry.Reason ?? DBNull.Value);
                if (!creating) cmd.Parameters.AddWithValue("id", entry.Id);
                await using var reader = await cmd.ExecuteReaderAsync(ct);
                if (!await reader.ReadAsync(ct))
                    return ServiceResponse<DhcpBlockedMac>.Fail("That entry no longer exists — refresh the list.");
                entry.Id = reader.GetGuid(0);
                entry.CreatedAt = reader.GetDateTime(1);
            }

            // Kick it off the network now: drop its lease(s) here and in the DHCP server's cache.
            var released = new List<IPAddress>();
            await using (var purge = new NpgsqlCommand(
                "DELETE FROM dhcp_leases WHERE mac_address = @mac RETURNING ip_address", conn, tx))
            {
                purge.Parameters.AddWithValue("mac", entry.MacAddress);
                await using var reader = await purge.ExecuteReaderAsync(ct);
                while (await reader.ReadAsync(ct)) released.Add((IPAddress)reader.GetValue(0));
            }

            await tx.CommitAsync(ct);
            foreach (var ip in released)
                await notifier.NotifySubnetChangedAsync($"lease.release:{ip}", ct);

            var mac = FormatMac(entry.MacAddress);
            logger.LogInformation("DHCP block list: {Mac} {Action} ({Leases} lease(s) released)", mac, creating ? "blocked" : "updated", released.Count);
            return ServiceResponse<DhcpBlockedMac>.Ok(entry, released.Count > 0
                ? $"{mac} is blocked; its lease on {string.Join(", ", released)} was released."
                : $"{mac} is blocked — the DHCP server will ignore it.");
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            return ServiceResponse<DhcpBlockedMac>.Fail($"{FormatMac(entry.MacAddress)} is already on the block list.");
        }
    }

    public async Task<ServiceResponse<bool>> DeleteBlockedMacAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("DELETE FROM dhcp_mac_blocklist WHERE id = @id RETURNING mac_address", conn);
        cmd.Parameters.AddWithValue("id", id);
        var mac = await cmd.ExecuteScalarAsync(ct) as PhysicalAddress;
        if (mac is null) return ServiceResponse<bool>.Fail("That entry no longer exists — refresh the list.");
        logger.LogInformation("DHCP block list: {Mac} unblocked", FormatMac(mac));
        return ServiceResponse<bool>.Ok(true, $"{FormatMac(mac)} is unblocked — it gets an address on its next request.");
    }

    private static async Task<IReadOnlyList<DhcpBlockedMac>> ReadBlockedAsync(NpgsqlCommand cmd, CancellationToken ct)
    {
        var list = new List<DhcpBlockedMac>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            list.Add(new DhcpBlockedMac
            {
                Id = reader.GetGuid(0),
                MacAddress = (PhysicalAddress)reader.GetValue(1),
                Reason = reader.IsDBNull(2) ? null : reader.GetString(2),
                CreatedAt = reader.IsDBNull(3) ? default : reader.GetDateTime(3),
            });
        return list;
    }

    // ---------------- Trusted relay agents ----------------

    public async Task<IReadOnlyList<DhcpRelayAgent>> GetRelayAgentsAsync(CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "SELECT id, ip_address, description, trusted, created_at FROM dhcp_relay_agents ORDER BY ip_address", conn);
        return await ReadRelaysAsync(cmd, ct);
    }

    public async Task<DhcpRelayAgent?> GetRelayAgentAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "SELECT id, ip_address, description, trusted, created_at FROM dhcp_relay_agents WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        return (await ReadRelaysAsync(cmd, ct)).FirstOrDefault();
    }

    public async Task<ServiceResponse<DhcpRelayAgent>> SaveRelayAgentAsync(DhcpRelayAgent relay, CancellationToken ct = default)
    {
        var ip = relay.IpAddress;
        if (ip.AddressFamily != AddressFamily.InterNetwork || ip.Equals(IPAddress.Any) || ip.Equals(IPAddress.Broadcast)
            || IPAddress.IsLoopback(ip))
            return ServiceResponse<DhcpRelayAgent>.Fail("Enter the relay's IPv4 address — the giaddr it puts in relayed packets.");
        if (relay.Description is { Length: > 255 })
            return ServiceResponse<DhcpRelayAgent>.Fail("Description is at most 255 characters.");
        relay.Description = string.IsNullOrWhiteSpace(relay.Description) ? null : relay.Description.Trim();

        // Was any relay trusted before this write? The first trusted one switches enforcement on.
        var trustedBefore = (await GetRelayAgentsAsync(ct)).Any(r => r.Trusted && r.Id != relay.Id);

        await using var conn = await dataSource.OpenConnectionAsync(ct);
        try
        {
            var creating = relay.Id == Guid.Empty;
            await using var cmd = new NpgsqlCommand(creating
                ? "INSERT INTO dhcp_relay_agents (ip_address, description, trusted) VALUES (@ip, @desc, @trusted) RETURNING id, created_at"
                : "UPDATE dhcp_relay_agents SET ip_address = @ip, description = @desc, trusted = @trusted WHERE id = @id RETURNING id, created_at", conn);
            cmd.Parameters.AddWithValue("ip", ip);
            cmd.Parameters.AddWithValue("desc", (object?)relay.Description ?? DBNull.Value);
            cmd.Parameters.AddWithValue("trusted", relay.Trusted);
            if (!creating) cmd.Parameters.AddWithValue("id", relay.Id);
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            if (!await reader.ReadAsync(ct))
                return ServiceResponse<DhcpRelayAgent>.Fail("That relay no longer exists — refresh the list.");
            relay.Id = reader.GetGuid(0);
            relay.CreatedAt = reader.IsDBNull(1) ? default : reader.GetDateTime(1);
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            return ServiceResponse<DhcpRelayAgent>.Fail($"{ip} is already listed.");
        }

        logger.LogInformation("DHCP relay {Ip} saved (trusted={Trusted})", ip, relay.Trusted);
        var message = !relay.Trusted
            ? $"Relay {ip} is refused — packets it relays are dropped."
            : trustedBefore
                ? $"Relay {ip} is trusted."
                : $"Relay {ip} is trusted. Trusted-relay mode is now ON: packets from any other relay are dropped.";
        return ServiceResponse<DhcpRelayAgent>.Ok(relay, message);
    }

    public async Task<ServiceResponse<bool>> DeleteRelayAgentAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("DELETE FROM dhcp_relay_agents WHERE id = @id RETURNING ip_address", conn);
        cmd.Parameters.AddWithValue("id", id);
        if (await cmd.ExecuteScalarAsync(ct) is not IPAddress ip)
            return ServiceResponse<bool>.Fail("That relay no longer exists — refresh the list.");

        await using var left = new NpgsqlCommand("SELECT EXISTS (SELECT 1 FROM dhcp_relay_agents WHERE trusted)", conn);
        var stillEnforced = (bool)(await left.ExecuteScalarAsync(ct))!;
        logger.LogInformation("DHCP relay {Ip} removed", ip);
        return ServiceResponse<bool>.Ok(true, stillEnforced
            ? $"Relay {ip} removed — packets it relays are now dropped."
            : $"Relay {ip} removed. No relay is trusted any more: every relay is answered again.");
    }

    private static async Task<IReadOnlyList<DhcpRelayAgent>> ReadRelaysAsync(NpgsqlCommand cmd, CancellationToken ct)
    {
        var list = new List<DhcpRelayAgent>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            list.Add(new DhcpRelayAgent
            {
                Id = reader.GetGuid(0),
                IpAddress = (IPAddress)reader.GetValue(1),
                Description = reader.IsDBNull(2) ? null : reader.GetString(2),
                Trusted = reader.GetBoolean(3),
                CreatedAt = reader.IsDBNull(4) ? default : reader.GetDateTime(4),
            });
        return list;
    }

    private static string FormatMac(PhysicalAddress mac) => string.Join(":", mac.GetAddressBytes().Select(b => b.ToString("X2")));
}
