using Microsoft.Extensions.Logging;
using Npgsql;

namespace NetFirewall.Services.Dhcp;

public sealed class DhcpCacheNotifier : IDhcpCacheNotifier
{
    private readonly NpgsqlDataSource _ds;
    private readonly ILogger<DhcpCacheNotifier> _logger;

    public DhcpCacheNotifier(NpgsqlDataSource ds, ILogger<DhcpCacheNotifier> logger)
    {
        _ds = ds;
        _logger = logger;
    }

    public async Task NotifySubnetChangedAsync(string reason, CancellationToken ct = default)
    {
        try
        {
            await using var conn = await _ds.OpenConnectionAsync(ct);
            // Channel + payload are quoted server-side; keep payload short — Postgres caps at 8000 bytes.
            await using var cmd = new NpgsqlCommand($"NOTIFY {IDhcpCacheNotifier.SubnetChannel}, @p", conn);
            cmd.Parameters.AddWithValue("p", reason);
            await cmd.ExecuteNonQueryAsync(ct);
            _logger.LogDebug("Sent NOTIFY {Channel}: {Reason}", IDhcpCacheNotifier.SubnetChannel, reason);
        }
        catch (Exception ex)
        {
            // A failed notify shouldn't fail the original write — cache will eventually
            // refresh on its 5-minute TTL. Log and swallow.
            _logger.LogWarning(ex, "NOTIFY {Channel} failed; cache will lag until TTL expires", IDhcpCacheNotifier.SubnetChannel);
        }
    }
}
