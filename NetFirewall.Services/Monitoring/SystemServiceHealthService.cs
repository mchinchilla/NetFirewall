using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.Monitoring;

[SupportedOSPlatform("linux")]
public sealed class SystemServiceHealthService : ISystemServiceHealthService
{
    private readonly IProcessRunner _runner;
    private readonly ILogger<SystemServiceHealthService> _logger;

    // Units that matter for a NetFirewall deployment. Keep in sync with the
    // operator-facing names. If a unit isn't installed (e.g., no DHCP server
    // configured), systemctl reports "not-found" and we surface that.
    private static readonly (string Unit, string Display)[] WatchedUnits = new[]
    {
        // The standalone netfirewall-wanmonitor.service was absorbed into the
        // daemon as a HostedService — no longer listed here.
        ("netfirewall-daemon.service",    "Daemon"),
        ("netfirewall-web.service",       "Web"),
        ("netfirewall-bootstrap.service", "Bootstrap"),
        ("netfirewall-dhcp.service",      "DHCP server"),
        ("postgresql.service",            "PostgreSQL"),
        ("nginx.service",                 "nginx"),
        // WireGuard is NOT a unit here: the daemon brings each interface up with `wg-quick up`
        // directly, so `wg-quick@wg0.service` always read "not-found" — and assumed one wg0.
        // Every configured interface is reported from its link instead (WireGuardEntriesAsync).
    };

    private readonly NetFirewall.Services.Network.INetworkLinkProbe? _links;
    private readonly IServiceScopeFactory? _scopes;

    public SystemServiceHealthService(
        IProcessRunner runner,
        ILogger<SystemServiceHealthService> logger,
        NetFirewall.Services.Network.INetworkLinkProbe? links = null,
        IServiceScopeFactory? scopes = null)
    {
        _runner = runner;
        _logger = logger;
        _links = links;
        _scopes = scopes;
    }

    /// <summary>
    /// One entry per configured WireGuard interface (server and every outbound connection):
    /// active = the link exists, inactive = configured but down, "disabled" when switched off.
    /// IWireGuardService is scoped, so it is resolved per call. Fail-soft: no DB, no entries.
    /// </summary>
    private async Task<IEnumerable<ServiceHealth>> WireGuardEntriesAsync(CancellationToken ct)
    {
        if (_links is null || _scopes is null) return [];
        try
        {
            await using var scope = _scopes.CreateAsyncScope();
            var wg = scope.ServiceProvider.GetRequiredService<NetFirewall.Services.Vpn.IWireGuardService>();
            var servers = await wg.ListServersAsync(ct);
            return servers.Select(s =>
            {
                var up = _links.Exists(s.Name);
                var role = string.Equals(s.Mode, "client", StringComparison.OrdinalIgnoreCase) ? "outbound" : "VPN server";
                return new ServiceHealth(
                    UnitName: $"wireguard:{s.Name}",
                    DisplayName: $"WireGuard {s.Name} ({role})",
                    ActiveState: s.Enabled ? (up ? "active" : "inactive") : "inactive",
                    SubState: s.Enabled ? (up ? "link up" : "link down") : "disabled",
                    Enabled: s.Enabled,
                    SinceUtc: null,
                    StatusText: null);
            }).ToList();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "WireGuard interfaces unavailable for the service health list");
            return [];
        }
    }

    public async Task<IReadOnlyList<ServiceHealth>> GetAllAsync(CancellationToken ct = default)
    {
        var results = new List<ServiceHealth>(WatchedUnits.Length);

        foreach (var (unit, display) in WatchedUnits)
        {
            var health = await QueryOneAsync(unit, display, ct);
            results.Add(health);
        }
        results.AddRange(await WireGuardEntriesAsync(ct));
        return results;
    }

    private async Task<ServiceHealth> QueryOneAsync(string unit, string display, CancellationToken ct)
    {
        // `systemctl show` is one syscall that returns ActiveState, SubState,
        // UnitFileState, ActiveEnterTimestamp, StatusText in one go. Parse
        // KEY=value lines.
        try
        {
            var result = await _runner.RunAsync(
                "systemctl",
                $"show {unit} --no-page --property=ActiveState,SubState,UnitFileState,ActiveEnterTimestamp,StatusText",
                TimeSpan.FromSeconds(3),
                ct);

            // systemctl show always returns exit 0 even for unknown units —
            // ActiveState comes back as "inactive" + UnitFileState="not-found".
            var fields = ParseFields(result.Output);
            var active   = fields.GetValueOrDefault("ActiveState", "unknown");
            var sub      = fields.GetValueOrDefault("SubState");
            var fileState= fields.GetValueOrDefault("UnitFileState", "");
            var sinceStr = fields.GetValueOrDefault("ActiveEnterTimestamp");
            var statusTxt= fields.GetValueOrDefault("StatusText");

            DateTime? since = null;
            // systemd timestamp format: "Sat 2026-05-17 01:50:32 CST"
            if (!string.IsNullOrEmpty(sinceStr) &&
                DateTime.TryParseExact(sinceStr,
                    new[] { "ddd yyyy-MM-dd HH:mm:ss zzz", "ddd yyyy-MM-dd HH:mm:ss" },
                    CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var parsed))
            {
                since = parsed.ToUniversalTime();
            }

            return new ServiceHealth(
                UnitName:   unit,
                DisplayName: display,
                ActiveState: active,
                SubState:    string.IsNullOrEmpty(sub) ? null : sub,
                Enabled:     fileState == "enabled" || fileState == "alias",
                SinceUtc:    since,
                StatusText:  string.IsNullOrEmpty(statusTxt) ? null : statusTxt);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "systemctl show {Unit} failed", unit);
            return new ServiceHealth(unit, display, "unknown", null, false, null, ex.Message);
        }
    }

    private static Dictionary<string, string> ParseFields(string output)
    {
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var eq = line.IndexOf('=');
            if (eq <= 0) continue;
            dict[line[..eq]] = line[(eq + 1)..].Trim();
        }
        return dict;
    }
}
