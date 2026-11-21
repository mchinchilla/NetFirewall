using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NetFirewall.Models;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Firewall;
using Npgsql;

namespace NetFirewall.Services.Vpn;

/// <summary>A split awaiting confirmation (the banner + the watchdog read it).</summary>
public sealed record WgSplitPending(Guid Id, string SourceName, string ServerName, DateTime DeadlineUtc);

/// <summary>Split a dual-role interface, with a confirm-or-revert window. See <see cref="WireGuardSplitPlanner"/>.</summary>
public interface IWireGuardSplitService
{
    Task<WgSplitPlan?> PlanAsync(string iface, IReadOnlyCollection<string>? serverAddresses = null, CancellationToken ct = default);
    Task<ServiceResponse<WgSplitPending>> ExecuteAsync(string iface, IReadOnlyCollection<string> serverAddresses, string? user, CancellationToken ct = default);
    Task<WgSplitPending?> PendingAsync(CancellationToken ct = default);
    Task<ServiceResponse<object>> ConfirmAsync(Guid journalId, CancellationToken ct = default);
    Task<ServiceResponse<object>> RevertAsync(Guid journalId, string reason, CancellationToken ct = default);
}

/// <summary>
/// Executes a <see cref="WgSplitPlan"/>: new server interface (same key + port, the server
/// addresses, the inbound peers moved with their ids), the source kept as the outbound link,
/// forwarding rebuilt for the moved peers, then applied in the ONLY working order — the source
/// first (it releases the listen port), the new server second (binds it), the firewall last. Any
/// apply failure reverts at once. Otherwise the split stays PENDING until the operator confirms;
/// the watchdog reverts it at the deadline (they may be connected through the tunnel being split).
/// </summary>
public sealed class WireGuardSplitService(
    IWireGuardService wg,
    IVpnRoutingService routing,
    IFirewallService fw,
    IWireGuardSplitKernel kernel,
    NpgsqlDataSource ds,
    ILogger<WireGuardSplitService> logger) : IWireGuardSplitService
{
    public static readonly TimeSpan ConfirmWindow = TimeSpan.FromMinutes(10);

    private sealed record Snapshot(Guid SourceId, string AddressCidr, int ListenPort, string Mode, bool TableOff,
        Guid ServerId, Guid[] MovedPeerIds);

    public async Task<WgSplitPlan?> PlanAsync(string iface, IReadOnlyCollection<string>? serverAddresses = null, CancellationToken ct = default)
    {
        var source = await wg.GetServerByNameAsync(iface, ct);
        if (source is null) return null;
        var peers = await wg.GetPeersAsync(source.Id, ct);
        var names = (await wg.ListServersAsync(ct)).Select(s => s.Name).ToList();
        var fwIface = await fw.GetInterfaceByNameAsync(source.Name, ct);
        return WireGuardSplitPlanner.Plan(source, peers, names, fwIface?.Id,
            await fw.GetFilterRulesAsync(null, ct), await fw.GetNatRulesAsync(ct), serverAddresses);
    }

    public async Task<ServiceResponse<WgSplitPending>> ExecuteAsync(string iface, IReadOnlyCollection<string> serverAddresses, string? user, CancellationToken ct = default)
    {
        var plan = await PlanAsync(iface, serverAddresses, ct);
        if (plan is null) return ServiceResponse<WgSplitPending>.Fail($"No WireGuard interface '{iface}'.");
        if (!plan.CanExecute) return ServiceResponse<WgSplitPending>.Fail(string.Join(" ", plan.Blockers));
        if (await PendingAsync(ct) is { } other)
            return ServiceResponse<WgSplitPending>.Fail($"A split of {other.SourceName} is still waiting for confirmation.");

        var source = (await wg.GetServerByNameAsync(iface, ct))!;
        var server = new WgServer
        {
            Name = plan.ServerName, Mode = "server", PrivateKey = source.PrivateKey, PublicKey = source.PublicKey,
            ListenPort = plan.ListenPort, AddressCidr = string.Join(", ", plan.AddressesToServer),
            Dns = source.Dns, Mtu = source.Mtu, TableOff = false, Enabled = true,
        };
        server = await wg.SaveServerAsync(server, ct);
        var snapshot = new Snapshot(source.Id, source.AddressCidr, source.ListenPort, source.Mode, source.TableOff,
            server.Id, plan.PeersToServer.Select(p => p.Id).ToArray());
        var pending = await InsertJournalAsync(plan, snapshot, user, ct);

        try
        {
            source.AddressCidr = string.Join(", ", plan.AddressesKept);
            source.ListenPort = 0;
            source.Mode = "client";
            source.TableOff = true;
            await wg.SaveServerAsync(source, ct);

            await EnsureFwInterfaceAsync(server, ct);
            foreach (var p in plan.PeersToServer) await routing.RemovePeerForwardingAsync(source, p, ct);
            await wg.MovePeersAsync(snapshot.MovedPeerIds, server.Id, ct);
            foreach (var p in plan.PeersToServer) await routing.EnsurePeerForwardingAsync(server, p, ct);

            // Order matters: the source releases the port before the server binds it.
            await RequireAsync(kernel.ApplyInterfaceAsync(source.Name, ct), $"apply {source.Name}");
            await RequireAsync(kernel.ApplyInterfaceAsync(server.Name, ct), $"apply {server.Name}");
            await RequireAsync(kernel.ApplyFirewallAsync(ct), "firewall apply");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Split of {Iface} failed — reverting", iface);
            var reverted = await RevertAsync(pending.Id, $"apply failed: {ex.Message}", ct);
            return ServiceResponse<WgSplitPending>.Fail($"The split failed ({ex.Message}) and was reverted{(reverted.Success ? "" : " — but the revert also failed, check the VPN pages")}.");
        }

        logger.LogWarning("Split {Source} → {Source} (outbound) + {Server} (server); confirm by {Deadline:u}", iface, iface, server.Name, pending.DeadlineUtc);
        return ServiceResponse<WgSplitPending>.Ok(pending,
            $"Split applied: {server.Name} is now the VPN server. Clients reconnect within ~15 s. Confirm within {ConfirmWindow.TotalMinutes:0} minutes or it reverts.");
    }

    public async Task<WgSplitPending?> PendingAsync(CancellationToken ct = default)
    {
        await using var conn = await ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "SELECT id, source_name, server_name, deadline FROM vpn_split_journal WHERE state = 'pending' LIMIT 1", conn);
        await using var r = await cmd.ExecuteReaderAsync(ct);
        return await r.ReadAsync(ct) ? new WgSplitPending(r.GetGuid(0), r.GetString(1), r.GetString(2), r.GetDateTime(3)) : null;
    }

    public async Task<ServiceResponse<object>> ConfirmAsync(Guid journalId, CancellationToken ct = default) =>
        await FinishAsync(journalId, "confirmed", ct)
            ? ServiceResponse<object>.Ok(new { }, "Split kept.")
            : ServiceResponse<object>.Fail("There is no split waiting for confirmation.");

    /// <summary>
    /// Restore the snapshot. The journal row is held (<c>FOR UPDATE</c>) for the whole revert, so
    /// the operator confirming in the Web and the watchdog reverting in the daemon can't both win:
    /// whichever comes second sees no pending split. The kernel steps are re-applied from the
    /// restored database rows, so a revert that fails half-way can simply be retried by hand.
    /// </summary>
    public async Task<ServiceResponse<object>> RevertAsync(Guid journalId, string reason, CancellationToken ct = default)
    {
        await using var conn = await ds.OpenConnectionAsync(ct);
        await using var tx = await conn.BeginTransactionAsync(ct);

        Snapshot? s;
        await using (var cmd = new NpgsqlCommand(
            "SELECT snapshot::text FROM vpn_split_journal WHERE id = @id AND state = 'pending' FOR UPDATE", conn, tx))
        {
            cmd.Parameters.AddWithValue("id", journalId);
            s = await cmd.ExecuteScalarAsync(ct) is string json ? JsonSerializer.Deserialize<Snapshot>(json) : null;
        }
        if (s is null) return ServiceResponse<object>.Fail("There is no split waiting to be reverted.");

        try
        {
            var source = await wg.GetServerByIdAsync(s.SourceId, ct) ?? throw new InvalidOperationException("the original interface is gone");
            var server = await wg.GetServerByIdAsync(s.ServerId, ct);
            if (server is not null)
            {
                foreach (var p in (await wg.GetPeersAsync(server.Id, ct)).Where(p => s.MovedPeerIds.Contains(p.Id)))
                    await routing.RemovePeerForwardingAsync(server, p, ct);
                // Release the listen port first. Not fatal: a link that is already down is fine,
                // and if the port really is still held the source's apply below fails loudly.
                var stop = await kernel.StopInterfaceAsync(server.Name, ct);
                if (!stop.Success) logger.LogWarning("Revert: stopping {Server} failed: {Message}", server.Name, stop.Message);
            }
            await wg.MovePeersAsync(s.MovedPeerIds, source.Id, ct);
            source.AddressCidr = s.AddressCidr; source.ListenPort = s.ListenPort; source.Mode = s.Mode; source.TableOff = s.TableOff;
            await wg.SaveServerAsync(source, ct);
            foreach (var p in (await wg.GetPeersAsync(source.Id, ct)).Where(p => s.MovedPeerIds.Contains(p.Id)))
                await routing.EnsurePeerForwardingAsync(source, p, ct);
            if (server is not null)
            {
                if (await fw.GetInterfaceByNameAsync(server.Name, ct) is { } fi) await fw.DeleteInterfaceAsync(fi.Id, ct);
                await wg.DeleteServerAsync(server.Id, ct);
            }
            await RequireAsync(kernel.ApplyInterfaceAsync(source.Name, ct), $"apply {source.Name}");
            await RequireAsync(kernel.ApplyFirewallAsync(ct), "firewall apply");
            await SetStateAsync(conn, tx, journalId, "reverted", ct);
            await tx.CommitAsync(ct);
            logger.LogWarning("Split of {Source} reverted: {Reason}", source.Name, reason);
            return ServiceResponse<object>.Ok(new { }, $"Split reverted ({reason}). {source.Name} is back to doing both jobs.");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Reverting split {Id} failed", journalId);
            await SetStateAsync(conn, tx, journalId, "revert_failed", ct);
            await tx.CommitAsync(ct);
            return ServiceResponse<object>.Fail($"Reverting the split failed: {ex.Message}. Check both interfaces on the VPN pages.");
        }
    }

    private async Task EnsureFwInterfaceAsync(WgServer server, CancellationToken ct)
    {
        if (await fw.GetInterfaceByNameAsync(server.Name, ct) is not null) return;
        await fw.CreateInterfaceAsync(new FwInterface
        {
            Name = server.Name, Type = "VPN", Role = "wireguard_tunnel", AddressingMode = "static",
            Description = $"{VpnRoutingService.AutoTag} WireGuard VPN server", Enabled = true,
        }, ct);
    }

    private static async Task RequireAsync<T>(Task<ServiceResponse<T>> call, string what)
    {
        var r = await call;
        if (!r.Success) throw new InvalidOperationException($"{what}: {r.Message}");
    }

    private async Task<WgSplitPending> InsertJournalAsync(WgSplitPlan plan, Snapshot snapshot, string? user, CancellationToken ct)
    {
        var deadline = DateTime.UtcNow + ConfirmWindow;
        await using var conn = await ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("""
            INSERT INTO vpn_split_journal (source_name, server_name, snapshot, state, deadline, created_by)
            VALUES (@src, @srv, @snap::jsonb, 'pending', @deadline, @user) RETURNING id
            """, conn);
        cmd.Parameters.AddWithValue("src", plan.SourceName);
        cmd.Parameters.AddWithValue("srv", plan.ServerName);
        cmd.Parameters.AddWithValue("snap", JsonSerializer.Serialize(snapshot));
        cmd.Parameters.AddWithValue("deadline", deadline);
        cmd.Parameters.AddWithValue("user", (object?)user ?? DBNull.Value);
        var id = (Guid)(await cmd.ExecuteScalarAsync(ct))!;
        return new WgSplitPending(id, plan.SourceName, plan.ServerName, deadline);
    }

    private static async Task SetStateAsync(NpgsqlConnection conn, NpgsqlTransaction tx, Guid id, string state, CancellationToken ct)
    {
        await using var cmd = new NpgsqlCommand(
            "UPDATE vpn_split_journal SET state = @state, finished_at = now() WHERE id = @id", conn, tx);
        cmd.Parameters.AddWithValue("id", id);
        cmd.Parameters.AddWithValue("state", state);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private async Task<bool> FinishAsync(Guid id, string state, CancellationToken ct)
    {
        await using var conn = await ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "UPDATE vpn_split_journal SET state = @state, finished_at = now() WHERE id = @id AND state = 'pending'", conn);
        cmd.Parameters.AddWithValue("id", id);
        cmd.Parameters.AddWithValue("state", state);
        return await cmd.ExecuteNonQueryAsync(ct) > 0;
    }
}

/// <summary>
/// Reverts a split nobody confirmed in time. Runs in the DAEMON: the revert has to reach the
/// kernel with no operator around (that is the point — they may have cut themselves off through
/// the tunnel being split), and only the daemon can do that without a session. It used to run in
/// the Web, whose daemon calls carried no session outside a request and were refused with 401.
/// </summary>
public sealed class WireGuardSplitWatchdog(
    IServiceScopeFactory scopes,
    ILogger<WireGuardSplitWatchdog> logger) : Microsoft.Extensions.Hosting.BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(20));
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await using var scope = scopes.CreateAsyncScope();
                var split = scope.ServiceProvider.GetRequiredService<IWireGuardSplitService>();
                if (await split.PendingAsync(stoppingToken) is { } p && p.DeadlineUtc <= DateTime.UtcNow)
                    await split.RevertAsync(p.Id, "not confirmed in time", stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UndefinedTable) { /* 00050 not applied */ }
            catch (Exception ex) { logger.LogWarning(ex, "Split watchdog check failed"); }
        }
    }
}
