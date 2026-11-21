using NetFirewall.Models;
using NetFirewall.Services.Daemon;
using NetFirewall.Services.Firewall;

namespace NetFirewall.Services.Vpn;

/// <summary>
/// The three kernel steps a WireGuard split or its revert needs. Two implementations, because
/// the split runs in two processes: the operator's execute / confirm / revert run in the Web and
/// reach the kernel through the daemon socket with the operator's (elevated) session; the
/// watchdog's automatic revert runs inside the daemon, where there is no session to send and the
/// kernel is reached in-process.
/// </summary>
public interface IWireGuardSplitKernel
{
    /// <summary>Write the interface's config, bring it up and re-install its policy routes.</summary>
    Task<ServiceResponse<object>> ApplyInterfaceAsync(string name, CancellationToken ct = default);

    /// <summary>Bring the interface down (releases its listen port).</summary>
    Task<ServiceResponse<object>> StopInterfaceAsync(string name, CancellationToken ct = default);

    /// <summary>Regenerate and load the nftables ruleset from the database.</summary>
    Task<ServiceResponse<object>> ApplyFirewallAsync(CancellationToken ct = default);
}

/// <summary>Web side: through the daemon socket, carrying the operator's session.</summary>
public sealed class DaemonWireGuardSplitKernel(IDaemonClient daemon) : IWireGuardSplitKernel
{
    public async Task<ServiceResponse<object>> ApplyInterfaceAsync(string name, CancellationToken ct = default) =>
        Plain(await daemon.ApplyWireGuardAsync(name, ct));

    public async Task<ServiceResponse<object>> StopInterfaceAsync(string name, CancellationToken ct = default) =>
        Plain(await daemon.StopWireGuardAsync(name, ct));

    public async Task<ServiceResponse<object>> ApplyFirewallAsync(CancellationToken ct = default) =>
        Plain(await daemon.ApplyFirewallAsync(ct));

    private static ServiceResponse<object> Plain<T>(ServiceResponse<T> r) =>
        r.Success
            ? ServiceResponse<object>.Ok(new { }, r.Message ?? "")
            : ServiceResponse<object>.Fail(r.Message ?? "the daemon refused the request");
}

/// <summary>
/// Daemon side: the same steps the <c>/v1/wireguard/{apply,stop}</c> and <c>/v1/firewall/apply</c>
/// endpoints run, called in-process (the daemon already holds the capabilities). Applies are
/// recorded in apply-history like any other, attributed to <see cref="Actor"/>.
/// </summary>
public sealed class InProcessWireGuardSplitKernel(
    IWireGuardService data,
    IWireGuardBringUpService bringUp,
    IWireGuardApplyService wg,
    INftApplyService nft,
    IApplyHistoryService history) : IWireGuardSplitKernel
{
    public const string Actor = "split-watchdog";

    public async Task<ServiceResponse<object>> ApplyInterfaceAsync(string name, CancellationToken ct = default)
    {
        var server = await data.GetServerByNameAsync(name, ct);
        if (server is null) return ServiceResponse<object>.Fail($"No WireGuard interface '{name}'.");

        var result = await bringUp.ApplyAsync(server, await data.GetPeersAsync(server.Id, ct), ct);
        var msg = result.Describe(server.Name);
        await history.RecordAsync("wireguard", result.Success, result.Apply.ExitCode, msg, Actor, ct);
        return result.Success ? ServiceResponse<object>.Ok(new { }, msg) : ServiceResponse<object>.Fail(msg);
    }

    public async Task<ServiceResponse<object>> StopInterfaceAsync(string name, CancellationToken ct = default)
    {
        var result = await wg.StopAsync(name, ct);
        return result.Success
            ? ServiceResponse<object>.Ok(new { }, $"WireGuard {name} stopped.")
            : ServiceResponse<object>.Fail(result.Error ?? $"wg stop {name} failed");
    }

    public async Task<ServiceResponse<object>> ApplyFirewallAsync(CancellationToken ct = default)
    {
        var result = await nft.ApplyConfigurationAsync(ct);
        var msg = result.Success ? "nftables applied." : $"nftables apply failed: {result.Error}";
        await history.RecordAsync("nftables", result.Success, result.ExitCode, msg, Actor, ct);
        return result.Success ? ServiceResponse<object>.Ok(new { }, msg) : ServiceResponse<object>.Fail(msg);
    }
}
