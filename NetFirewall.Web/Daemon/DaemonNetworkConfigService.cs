using NetFirewall.Services.Daemon;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.System;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;

namespace NetFirewall.Web.Daemon;

/// <summary>
/// <see cref="INetworkConfigService"/> implementation that delegates write
/// operations to the daemon over a Unix socket while keeping read-only ops
/// (config preview, file path, validation) local — they don't need root and
/// the round trip would be wasted latency.
///
/// Wired in DI when <c>Daemon:Enabled = true</c>; otherwise the Web keeps
/// using the in-process writers directly (the legacy path).
/// </summary>
public sealed class DaemonNetworkConfigService : INetworkConfigService
{
    private readonly IDaemonClient _daemon;
    private readonly INetworkConfigService _localWriter;
    private readonly IFirewallService _firewall;

    public DaemonNetworkConfigService(
        IDaemonClient daemon,
        INetworkConfigService localWriter,
        IFirewallService firewall)
    {
        _daemon = daemon;
        _localWriter = localWriter;
        _firewall = firewall;
    }

    /// <inheritdoc />
    public NetworkConfigMethod ConfigMethod => _localWriter.ConfigMethod;

    /// <inheritdoc />
    public string GetConfigFilePath(FwInterface iface) => _localWriter.GetConfigFilePath(iface);

    /// <inheritdoc />
    public Task<string> GenerateConfigAsync(FwInterface iface, IEnumerable<FwStaticRoute>? routes = null)
        => _localWriter.GenerateConfigAsync(iface, routes);

    /// <inheritdoc />
    public Task<bool> ValidateConfigAsync(string config) => _localWriter.ValidateConfigAsync(config);

    /// <inheritdoc />
    /// <remarks>
    /// Read-only; delegated to the local reader. In production the Web's sandbox
    /// may not be able to read the config files, so this can return null — that's
    /// fine: the wizard gets the authoritative addressing mode through the daemon's
    /// /interfaces/discover endpoint (which enriches it server-side), not here.
    /// </remarks>
    public Task<string?> DetectAddressingModeAsync(string interfaceName, CancellationToken ct = default)
        => _localWriter.DetectAddressingModeAsync(interfaceName, ct);

    /// <inheritdoc />
    public async Task<NetworkApplyResult> ApplyConfigAsync(FwInterface iface, IEnumerable<FwStaticRoute>? routes = null)
    {
        // The daemon owns the live config — re-fetching routes there avoids
        // a stale snapshot if the caller passed an out-of-date list.
        var envelope = await _daemon.ApplyInterfaceAsync(iface.Id);
        return ToResult(envelope);
    }

    /// <inheritdoc />
    public async Task<NetworkApplyResult> RestartNetworkingAsync()
    {
        var envelope = await _daemon.RestartNetworkingAsync();
        return ToResult(envelope);
    }

    private static NetworkApplyResult ToResult(NetFirewall.Models.ServiceResponse<NetworkApplyResult> envelope) =>
        envelope.Data ?? new NetworkApplyResult
        {
            Success = envelope.Success,
            Message = envelope.Message ?? (envelope.Success ? "ok" : "daemon failure"),
            ExitCode = envelope.Success ? 0 : -1
        };
}
