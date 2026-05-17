using System.Globalization;
using System.Runtime.Versioning;
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
        ("netfirewall-daemon.service",   "Daemon"),
        ("netfirewall-web.service",      "Web"),
        ("netfirewall-dhcp.service",     "DHCP server"),
        ("netfirewall-wanmonitor.service","WAN monitor"),
        ("postgresql.service",           "PostgreSQL"),
        ("nginx.service",                "nginx"),
        ("wg-quick@wg0.service",         "WireGuard wg0"),
    };

    public SystemServiceHealthService(IProcessRunner runner, ILogger<SystemServiceHealthService> logger)
    {
        _runner = runner;
        _logger = logger;
    }

    public async Task<IReadOnlyList<ServiceHealth>> GetAllAsync(CancellationToken ct = default)
    {
        var results = new List<ServiceHealth>(WatchedUnits.Length);

        foreach (var (unit, display) in WatchedUnits)
        {
            var health = await QueryOneAsync(unit, display, ct);
            results.Add(health);
        }
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
