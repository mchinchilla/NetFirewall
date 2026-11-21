using System.Collections.Frozen;
using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace NetFirewall.Services.Dhcp;

/// <inheritdoc cref="IDhcpBlocklistCache" />
public sealed class DhcpBlocklistCache(NpgsqlDataSource dataSource, ILogger<DhcpBlocklistCache> logger, TimeProvider? time = null)
    : NotifiedSnapshotCache<FrozenSet<string>>(time), IDhcpBlocklistCache
{
    public async ValueTask<bool> IsBlockedAsync(string mac, CancellationToken ct = default)
    {
        var key = DhcpReservationCache.MacKey(mac);
        if (key is null) return false;
        var blocked = await CurrentAsync(ct).ConfigureAwait(false);
        return blocked.Count > 0 && blocked.Contains(key);
    }

    protected override async Task<FrozenSet<string>> LoadAsync(CancellationToken ct)
    {
        var keys = new List<string>();
        await using var conn = await dataSource.OpenConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = new NpgsqlCommand("SELECT mac_address FROM dhcp_mac_blocklist", conn);
        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
            keys.Add(Convert.ToHexString(((PhysicalAddress)reader.GetValue(0)).GetAddressBytes()).ToLowerInvariant());
        logger.LogDebug("[BLOCKLIST] Cache loaded: {Count} blocked MAC(s)", keys.Count);
        return keys.ToFrozenSet(StringComparer.Ordinal);
    }
}
