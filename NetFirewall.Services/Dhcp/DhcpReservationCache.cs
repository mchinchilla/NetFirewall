using System.Collections.Frozen;
using System.Net;
using System.Net.NetworkInformation;
using Microsoft.Extensions.Logging;
using Npgsql;

namespace NetFirewall.Services.Dhcp;

/// <inheritdoc />
public sealed class DhcpReservationCache(NpgsqlDataSource dataSource, ILogger<DhcpReservationCache> logger, TimeProvider? time = null)
    : IDhcpReservationCache
{
    /// <summary>Reload even without a NOTIFY after this long (a dropped LISTEN connection).</summary>
    public static readonly TimeSpan MaxAge = TimeSpan.FromMinutes(5);

    private readonly TimeProvider _time = time ?? TimeProvider.System;
    private readonly SemaphoreSlim _load = new(1, 1);
    private volatile Snapshot? _snapshot;

    private sealed record Snapshot(
        FrozenDictionary<string, IPAddress> IpByMac,
        FrozenDictionary<IPAddress, string> MacByIp,
        FrozenDictionary<string, int> LeaseByMac,
        DateTimeOffset LoadedAt);

    public async ValueTask<IPAddress?> GetReservedIpAsync(string mac, CancellationToken ct = default)
    {
        var key = MacKey(mac);
        if (key is null) return null;
        var snap = await CurrentAsync(ct).ConfigureAwait(false);
        return snap.IpByMac.GetValueOrDefault(key);
    }

    public async ValueTask<int?> GetLeaseTimeAsync(string mac, CancellationToken ct = default)
    {
        var key = MacKey(mac);
        if (key is null) return null;
        var snap = await CurrentAsync(ct).ConfigureAwait(false);
        return snap.LeaseByMac.TryGetValue(key, out var seconds) ? seconds : null;
    }

    public async ValueTask<string?> GetOwnerMacAsync(IPAddress ip, CancellationToken ct = default)
    {
        var snap = await CurrentAsync(ct).ConfigureAwait(false);
        return snap.MacByIp.GetValueOrDefault(ip);
    }

    public void Invalidate() => _snapshot = null;

    private async ValueTask<Snapshot> CurrentAsync(CancellationToken ct)
    {
        var snap = _snapshot;
        if (snap is not null && _time.GetUtcNow() - snap.LoadedAt < MaxAge) return snap;

        await _load.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            snap = _snapshot;
            if (snap is not null && _time.GetUtcNow() - snap.LoadedAt < MaxAge) return snap;
            snap = await LoadAsync(ct).ConfigureAwait(false);
            _snapshot = snap;
            return snap;
        }
        finally
        {
            _load.Release();
        }
    }

    private async Task<Snapshot> LoadAsync(CancellationToken ct)
    {
        var byMac = new Dictionary<string, IPAddress>(StringComparer.Ordinal);
        var byIp = new Dictionary<IPAddress, string>();
        var leaseByMac = new Dictionary<string, int>(StringComparer.Ordinal);
        await using var conn = await dataSource.OpenConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = new NpgsqlCommand("SELECT mac_address, reserved_ip, lease_time FROM dhcp_mac_reservations", conn);
        await using var reader = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            var mac = (PhysicalAddress)reader.GetValue(0);
            var ip = (IPAddress)reader.GetValue(1);
            var key = Convert.ToHexString(mac.GetAddressBytes()).ToLowerInvariant();
            byMac[key] = ip;
            byIp[ip] = ColonForm(key);
            if (!reader.IsDBNull(2)) leaseByMac[key] = reader.GetInt32(2);
        }
        logger.LogDebug("[RESERVATION] Cache loaded: {Count} reservation(s)", byMac.Count);
        return new Snapshot(byMac.ToFrozenDictionary(StringComparer.Ordinal), byIp.ToFrozenDictionary(),
            leaseByMac.ToFrozenDictionary(StringComparer.Ordinal), _time.GetUtcNow());
    }

    /// <summary>"AA:BB-cc.dd…" → "aabbccdd…" (12 hex chars), or null when it isn't a MAC.</summary>
    internal static string? MacKey(string? mac)
    {
        if (string.IsNullOrEmpty(mac)) return null;
        Span<char> buf = stackalloc char[12];
        var n = 0;
        foreach (var c in mac)
        {
            if (c is ':' or '-' or '.') continue;
            if (!Uri.IsHexDigit(c) || n == 12) return null;
            buf[n++] = char.ToLowerInvariant(c);
        }
        return n == 12 ? new string(buf) : null;
    }

    private static string ColonForm(string key) =>
        string.Create(17, key, static (span, k) =>
        {
            for (int i = 0, j = 0; i < 12; i += 2)
            {
                if (i > 0) span[j++] = ':';
                span[j++] = k[i];
                span[j++] = k[i + 1];
            }
        });
}
