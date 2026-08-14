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
            // pg_notify() is the parameterizable form — `NOTIFY channel, @p`
            // is a utility statement and rejects bind parameters, so every
            // notify silently failed (the catch below ate it) and the DHCP
            // server's caches lagged on their TTL after every UI change.
            // Keep payload short — Postgres caps at 8000 bytes.
            await using var cmd = new NpgsqlCommand("SELECT pg_notify(@channel, @payload)", conn);
            cmd.Parameters.AddWithValue("channel", IDhcpCacheNotifier.SubnetChannel);
            cmd.Parameters.AddWithValue("payload", reason);
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
