using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace NetFirewall.Services.Dhcp;

/// <summary>One interval in which a device held an address.</summary>
public sealed record DhcpLeaseHistoryRow(long Id, string Mac, IPAddress Ip, string? Hostname, DateTime FirstSeen, DateTime LastSeen, DateTime? ClosedAt)
{
    public bool Current => ClosedAt is null;
}

/// <summary>Read side of dhcp_lease_history (written by the DHCP server's lease flush).</summary>
public interface IDhcpLeaseHistoryService
{
    /// <summary>Newest first, at most <paramref name="limit"/> intervals.</summary>
    Task<IReadOnlyList<DhcpLeaseHistoryRow>> RecentAsync(int limit = 5000, CancellationToken ct = default);
}

public sealed class DhcpLeaseHistoryService(NpgsqlDataSource ds) : IDhcpLeaseHistoryService
{
    public async Task<IReadOnlyList<DhcpLeaseHistoryRow>> RecentAsync(int limit = 5000, CancellationToken ct = default)
    {
        await using var conn = await ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("""
            SELECT id, mac_address, ip_address, hostname, first_seen, last_seen, closed_at
            FROM dhcp_lease_history ORDER BY last_seen DESC LIMIT @limit
            """, conn);
        cmd.Parameters.AddWithValue("limit", Math.Clamp(limit, 1, 50_000));
        await using var r = await cmd.ExecuteReaderAsync(ct);
        var list = new List<DhcpLeaseHistoryRow>();
        while (await r.ReadAsync(ct))
            list.Add(new DhcpLeaseHistoryRow(r.GetInt64(0),
                NetFirewall.Models.Wol.MacAddressText.Format(r.GetFieldValue<PhysicalAddress>(1).GetAddressBytes(), lowercase: true),
                r.GetFieldValue<IPAddress>(2), r.IsDBNull(3) ? null : r.GetString(3),
                r.GetDateTime(4), r.GetDateTime(5), r.IsDBNull(6) ? null : r.GetDateTime(6)));
        return list;
    }
}

/// <summary>Keeps dhcp_lease_history to 90 days (closed intervals only — a present device keeps its row).</summary>
public sealed class DhcpLeaseHistoryRetentionService(NpgsqlDataSource ds, ILogger<DhcpLeaseHistoryRetentionService> logger) : BackgroundService
{
    public static readonly TimeSpan Keep = TimeSpan.FromDays(90);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
        do
        {
            try
            {
                await using var conn = await ds.OpenConnectionAsync(stoppingToken);
                await using var cmd = new NpgsqlCommand(
                    "DELETE FROM dhcp_lease_history WHERE closed_at IS NOT NULL AND last_seen < now() - @keep", conn);
                cmd.Parameters.AddWithValue("keep", Keep);
                var pruned = await cmd.ExecuteNonQueryAsync(stoppingToken);
                if (pruned > 0) logger.LogInformation("Pruned {Count} lease history intervals older than {Days} days", pruned, Keep.TotalDays);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UndefinedTable) { /* migration 00049 not applied yet */ }
            catch (Exception ex) { logger.LogWarning(ex, "Lease history retention failed"); }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }
}
