using System.Net;
using System.Threading.Channels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Dhcp;
using Npgsql;

namespace NetFirewall.Services.Dhcp;

/// <summary>A DNS registration (on ACK) or removal (on RELEASE) to perform after the reply went out.</summary>
public sealed record DdnsWork(DdnsAction Action, string MacAddress, IPAddress IpAddress, string? Hostname, Guid? SubnetId);

public enum DdnsAction { Register, Remove }

/// <summary>Hand-off from the DHCP reply path to the DDNS worker. Never blocks, never throws.</summary>
public interface IDdnsUpdateQueue
{
    /// <summary>False when the queue is full (the oldest pending update is dropped instead) — never blocks a reply.</summary>
    bool TryEnqueue(DdnsWork work);
}

/// <summary>
/// RFC 2136 updates OFF the DHCP reply path. The DDNS code existed (DdnsService, config UI) but was
/// never called; calling it inline before the ACK would stall the single-consumer packet pipeline on
/// every slow or unreachable DNS server. Here the ACK goes out first and this worker registers /
/// removes the records afterwards, honouring the per-subnet DDNS config, and writes dhcp_ddns_log.
/// A RELEASE carries no hostname, so the removal takes it from the last successful registration of
/// that address in the log. Fail-soft per item: a DNS error is logged, never escapes (in .NET 11 an
/// exception leaving ExecuteAsync stops the host).
/// </summary>
public sealed class DdnsUpdateQueue(
    IServiceScopeFactory scopes,
    NpgsqlDataSource dataSource,
    ILogger<DdnsUpdateQueue> logger) : BackgroundService, IDdnsUpdateQueue
{
    private readonly Channel<DdnsWork> _work = Channel.CreateBounded<DdnsWork>(
        new BoundedChannelOptions(1024) { FullMode = BoundedChannelFullMode.DropOldest, SingleReader = true });

    public bool TryEnqueue(DdnsWork work) => _work.Writer.TryWrite(work);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await foreach (var work in _work.Reader.ReadAllAsync(stoppingToken).ConfigureAwait(false))
        {
            try
            {
                await ProcessAsync(work, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogWarning(ex, "DDNS {Action} for {Ip} ({Mac}) failed", work.Action, work.IpAddress, work.MacAddress);
            }
        }
    }

    /// <summary>One update. Internal for tests.</summary>
    internal async Task ProcessAsync(DdnsWork work, CancellationToken ct)
    {
        await using var scope = scopes.CreateAsyncScope();
        var ddns = scope.ServiceProvider.GetRequiredService<IDdnsService>();
        var config = await ddns.GetConfigForSubnetAsync(work.SubnetId, ct).ConfigureAwait(false);
        if (config is not { Enabled: true }) return;   // DDNS not configured for this subnet

        if (work.Action == DdnsAction.Register)
        {
            if (string.IsNullOrWhiteSpace(work.Hostname)) return;   // nothing to register
            var result = await ddns.UpdateLeaseRecordsAsync(work.Hostname, work.IpAddress, work.MacAddress, config, ct).ConfigureAwait(false);
            await LogAsync("add", work.Hostname, work.IpAddress, result, config, ct).ConfigureAwait(false);
        }
        else
        {
            var hostname = work.Hostname ?? await LastRegisteredHostnameAsync(work.IpAddress, ct).ConfigureAwait(false);
            if (hostname is null) return;   // never registered → nothing to remove
            var result = await ddns.RemoveLeaseRecordsAsync(hostname, work.IpAddress, config, ct).ConfigureAwait(false);
            await LogAsync("remove", hostname, work.IpAddress, result, config, ct).ConfigureAwait(false);
        }
    }

    private async Task<string?> LastRegisteredHostnameAsync(IPAddress ip, CancellationToken ct)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct).ConfigureAwait(false);
        await using var cmd = new NpgsqlCommand("""
            SELECT hostname FROM dhcp_ddns_log
            WHERE ip_address = @ip AND action = 'add_forward' AND success
            ORDER BY created_at DESC LIMIT 1
            """, conn);
        cmd.Parameters.AddWithValue("ip", ip);
        return await cmd.ExecuteScalarAsync(ct).ConfigureAwait(false) as string;
    }

    private async Task LogAsync(string verb, string hostname, IPAddress ip, DdnsUpdateResult result, DdnsConfig config, CancellationToken ct)
    {
        await using var conn = await dataSource.OpenConnectionAsync(ct).ConfigureAwait(false);
        await using var batch = new NpgsqlBatch(conn);
        foreach (var (kind, ok, error) in new[] { ("forward", result.ForwardSuccess, result.ForwardError), ("reverse", result.ReverseSuccess, result.ReverseError) })
        {
            if (!ok && string.IsNullOrEmpty(error)) continue;   // not attempted (e.g. reverse disabled)
            var c = new NpgsqlBatchCommand("""
                INSERT INTO dhcp_ddns_log (action, hostname, ip_address, fqdn, success, error_msg, dns_server)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                """);
            c.Parameters.Add(new NpgsqlParameter { Value = $"{verb}_{kind}" });
            c.Parameters.Add(new NpgsqlParameter { Value = hostname });
            c.Parameters.Add(new NpgsqlParameter { Value = ip });
            c.Parameters.Add(new NpgsqlParameter { Value = (object?)result.Fqdn ?? DBNull.Value });
            c.Parameters.Add(new NpgsqlParameter { Value = ok });
            c.Parameters.Add(new NpgsqlParameter { Value = (object?)error ?? DBNull.Value });
            c.Parameters.Add(new NpgsqlParameter { Value = (object?)config.DnsServer ?? DBNull.Value });
            batch.BatchCommands.Add(c);
        }
        if (batch.BatchCommands.Count > 0) await batch.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
        if (!result.Success)
            logger.LogWarning("DDNS {Verb} {Host} → {Ip}: forward={Fwd} reverse={Rev} ({Err})",
                verb, hostname, ip, result.ForwardSuccess, result.ReverseSuccess, result.ForwardError ?? result.ReverseError);
    }
}
