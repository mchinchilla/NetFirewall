using System.Net;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Dhcp;
using Npgsql;

namespace NetFirewall.Services.Dhcp;

/// <inheritdoc cref="IDhcpRelayTrustCache" />
public sealed class DhcpRelayTrustCache(NpgsqlDataSource dataSource, ILogger<DhcpRelayTrustCache> logger, TimeProvider? time = null)
    : NotifiedSnapshotCache<DhcpRelayPolicy>(time), IDhcpRelayTrustCache
{
    public ValueTask<DhcpRelayPolicy> GetPolicyAsync(CancellationToken ct = default) => CurrentAsync(ct);

    protected override async Task<DhcpRelayPolicy> LoadAsync(CancellationToken ct)
    {
        var relays = new List<DhcpRelayAgent>();
        await using var conn = await dataSource.OpenConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = new NpgsqlCommand("SELECT ip_address, COALESCE(trusted, true) FROM dhcp_relay_agents", conn);
        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
            relays.Add(new DhcpRelayAgent { IpAddress = (IPAddress)reader.GetValue(0), Trusted = reader.GetBoolean(1) });
        var policy = DhcpRelayPolicy.From(relays);
        logger.LogDebug("[RELAY] Trust cache loaded: {Count} relay(s), enforced={Enforced}", relays.Count, policy.IsEnforced);
        return policy;
    }
}
