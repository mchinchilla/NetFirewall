using System.Net;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NetFirewall.Services.Processes;
using Npgsql;

namespace NetFirewall.Services.Network;

/// <summary>
/// Keeps the firewall's DNS resolver (Unbound) answering for DHCP hostnames: every 30 s it renders
/// reservations + active leases (<see cref="LocalDnsZone"/>) into its own include,
/// netfirewall-hosts.conf, and reloads Unbound — only when the content changed, only when the DNS
/// forwarder is in use (its netfirewall.conf exists). unbound-checkconf guards every write: a bad
/// file is rolled back, never left for the next restart to choke on. Runs in the daemon (root).
/// Fail-soft: errors are logged, never escape ExecuteAsync (that would stop the host in .NET 11).
/// </summary>
public sealed class LocalDnsPublisherService(
    NpgsqlDataSource dataSource,
    IProcessRunner runner,
    ILogger<LocalDnsPublisherService> logger,
    string confDir = "/etc/unbound/unbound.conf.d") : BackgroundService
{
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(30);
    private string HostsFile => Path.Combine(confDir, "netfirewall-hosts.conf");
    private string ForwarderFile => Path.Combine(confDir, "netfirewall.conf");

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(Interval);
        do
        {
            try
            {
                await PublishOnceAsync(stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "Publishing DHCP hostnames to Unbound failed; retrying in {Interval}", Interval);
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false));
    }

    /// <summary>One pass. Returns what happened (for tests and the log). Internal.</summary>
    internal async Task<string> PublishOnceAsync(CancellationToken ct)
    {
        if (!File.Exists(ForwarderFile))
        {
            // Not using our resolver: make sure we don't leave names behind in a stock Unbound.
            if (File.Exists(HostsFile)) { File.Delete(HostsFile); await ReloadAsync(ct).ConfigureAwait(false); return "removed"; }
            return "inactive";
        }

        var (hosts, domains) = await LoadAsync(ct).ConfigureAwait(false);
        var content = LocalDnsZone.Render(hosts, domains);
        var previous = File.Exists(HostsFile) ? await File.ReadAllTextAsync(HostsFile, ct).ConfigureAwait(false) : null;
        if (previous == content) return "unchanged";

        // Write-then-rename: Unbound never sees a half-written file.
        var tmp = HostsFile + ".tmp";
        await File.WriteAllTextAsync(tmp, content, ct).ConfigureAwait(false);
        File.Move(tmp, HostsFile, overwrite: true);

        var check = await runner.RunAsync("unbound-checkconf", [], TimeSpan.FromSeconds(15), ct).ConfigureAwait(false);
        if (!check.Success)
        {
            if (previous is null) File.Delete(HostsFile); else await File.WriteAllTextAsync(HostsFile, previous, ct).ConfigureAwait(false);
            logger.LogError("Generated DNS host entries were rejected by unbound-checkconf ({Error}) — rolled back", check.Error?.Trim());
            return "rejected";
        }

        await ReloadAsync(ct).ConfigureAwait(false);
        logger.LogInformation("Published {Count} DHCP host names to Unbound", hosts.Count);
        return "published";
    }

    private async Task ReloadAsync(CancellationToken ct)
    {
        var reload = await runner.RunAsync("systemctl", ["reload", "unbound"], TimeSpan.FromSeconds(20), ct).ConfigureAwait(false);
        if (!reload.Success) logger.LogWarning("systemctl reload unbound failed (exit {Exit}): {Error}", reload.ExitCode, reload.Error?.Trim());
    }

    private async Task<(List<LocalDnsHost> Hosts, List<LocalDnsDomain> Domains)> LoadAsync(CancellationToken ct)
    {
        var hosts = new List<LocalDnsHost>();
        var domains = new List<LocalDnsDomain>();
        await using var conn = await dataSource.OpenConnectionAsync(ct).ConfigureAwait(false);
        await using (var cmd = new NpgsqlCommand("""
            SELECT hostname, reserved_ip, true FROM dhcp_mac_reservations WHERE hostname IS NOT NULL
            UNION ALL
            SELECT hostname, ip_address, false FROM dhcp_leases WHERE hostname IS NOT NULL AND end_time > now()
            ORDER BY 3 DESC, 2
            """, conn))
        await using (var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false))
            while (await r.ReadAsync(ct).ConfigureAwait(false))
                hosts.Add(new LocalDnsHost(r.GetString(0), r.GetFieldValue<IPAddress>(1), r.GetBoolean(2)));

        await using (var cmd = new NpgsqlCommand("SELECT network::text, domain_name FROM dhcp_subnets WHERE enabled", conn))
        await using (var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false))
            while (await r.ReadAsync(ct).ConfigureAwait(false))
                domains.Add(new LocalDnsDomain(r.GetString(0), r.IsDBNull(1) ? null : r.GetString(1)));
        return (hosts, domains);
    }
}
