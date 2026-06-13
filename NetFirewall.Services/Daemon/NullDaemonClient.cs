using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.Network;
using NetFirewall.Models.System;
using NetFirewall.Models.Vpn;

namespace NetFirewall.Services.Daemon;

/// <summary>
/// In-process stand-in for <see cref="IDaemonClient"/> used when
/// <c>Daemon:Enabled=false</c> (dev / single-process Web). Read-only probes
/// degrade quietly (alive=false, no live ruleset / WireGuard status). Apply /
/// crypto operations return a <see cref="ServiceResponse{T}"/> failure with
/// an explicit "daemon disabled" message — visible in the UI as a
/// non-shouting toast / error banner, not a 500.
///
/// The TOTP cipher path is NOT served by this class — when daemon is disabled,
/// <c>Program.cs</c> registers <see cref="NetFirewall.Services.Auth.AesGcmTotpSecretCipher"/>
/// directly, so callers go to the in-process AES cipher and never touch this stub.
/// EncryptTotpAsync / DecryptTotpAsync exist here only to satisfy the interface.
/// </summary>
public sealed class NullDaemonClient : IDaemonClient
{
    private const string DisabledMessage =
        "Daemon is disabled (Daemon:Enabled=false). This operation requires the netfirewall daemon — start it or run a full Linux deployment.";

    private static ServiceResponse<T> Disabled<T>() => ServiceResponse<T>.Fail(DisabledMessage);

    public Task<ServiceResponse<IReadOnlyList<FwInterface>>> ListInterfacesAsync(CancellationToken ct = default)
        => Task.FromResult(Disabled<IReadOnlyList<FwInterface>>());

    public Task<ServiceResponse<IReadOnlyList<InterfaceSuggestion>>> DiscoverInterfacesAsync(CancellationToken ct = default)
        => Task.FromResult(Disabled<IReadOnlyList<InterfaceSuggestion>>());

    public Task<ServiceResponse<RedetectResult>> RedetectInterfacesAsync(CancellationToken ct = default)
        => Task.FromResult(Disabled<RedetectResult>());

    public Task<ServiceResponse<FwInterface>> CreateInterfaceAsync(FwInterface iface, CancellationToken ct = default)
        => Task.FromResult(Disabled<FwInterface>());

    public Task<ServiceResponse<FwInterface>> UpdateInterfaceAsync(Guid id, FwInterface iface, CancellationToken ct = default)
        => Task.FromResult(Disabled<FwInterface>());

    public Task<ServiceResponse<NetworkApplyResult>> ApplyInterfaceAsync(Guid interfaceId, CancellationToken ct = default)
        => Task.FromResult(Disabled<NetworkApplyResult>());

    public Task<ServiceResponse<NetworkApplyResult>> RestartNetworkingAsync(CancellationToken ct = default)
        => Task.FromResult(Disabled<NetworkApplyResult>());

    public Task<ServiceResponse<NetworkApplyResult>> ApplyRouteAsync(Guid routeId, CancellationToken ct = default)
        => Task.FromResult(Disabled<NetworkApplyResult>());

    public Task<ServiceResponse<NetworkApplyResult>> RemoveRouteAsync(Guid routeId, CancellationToken ct = default)
        => Task.FromResult(Disabled<NetworkApplyResult>());

    public Task<ServiceResponse<NftApplyResultDto>> ApplyFirewallAsync(CancellationToken ct = default)
        => Task.FromResult(Disabled<NftApplyResultDto>());

    public Task<ServiceResponse<NftApplyResultDto>> ApplyQosAsync(CancellationToken ct = default)
        => Task.FromResult(Disabled<NftApplyResultDto>());

    public Task<string?> GetCurrentRulesetAsync(CancellationToken ct = default) =>
        Task.FromResult<string?>(null);

    public Task<bool> IsAliveAsync(CancellationToken ct = default) =>
        Task.FromResult(false);

    public Task<ServiceResponse<TuiLoginResult>> LoginAsync(TuiLoginRequest request, CancellationToken ct = default) =>
        Task.FromResult(Disabled<TuiLoginResult>());

    public Task<ServiceResponse<bool>> LogoutAsync(CancellationToken ct = default) =>
        Task.FromResult(Disabled<bool>());

    public Task<ServiceResponse<IReadOnlyList<RecoveryUserSummary>>> ListUsersForRecoveryAsync(CancellationToken ct = default)
        => Task.FromResult(Disabled<IReadOnlyList<RecoveryUserSummary>>());

    public Task<ServiceResponse<RecoveryActionResult>> RecoveryResetPasswordAsync(string username, string newPassword, CancellationToken ct = default)
        => Task.FromResult(Disabled<RecoveryActionResult>());

    public Task<ServiceResponse<RecoveryActionResult>> RecoveryDisableTotpAsync(string username, CancellationToken ct = default)
        => Task.FromResult(Disabled<RecoveryActionResult>());

    // The TOTP path goes through ITotpSecretCipher and is rebound to the
    // in-process AES cipher when daemon is off — this method shouldn't be
    // reached. If it ever is, throw loud so the misconfig is obvious.
    public Task<byte[]> EncryptTotpAsync(byte[] plaintext, CancellationToken ct = default) =>
        throw new InvalidOperationException(
            "EncryptTotpAsync called on NullDaemonClient — TOTP cipher should be AesGcmTotpSecretCipher when daemon is disabled. Misconfigured DI?");

    public Task<byte[]> DecryptTotpAsync(byte[] ciphertext, CancellationToken ct = default) =>
        throw new InvalidOperationException(
            "DecryptTotpAsync called on NullDaemonClient — TOTP cipher should be AesGcmTotpSecretCipher when daemon is disabled. Misconfigured DI?");

    public Task<ServiceResponse<TerminalTicketDto>> OpenTerminalAsync(string totpCode, CancellationToken ct = default)
        => Task.FromResult(Disabled<TerminalTicketDto>());

    public Task<System.Net.WebSockets.WebSocket> ConnectTerminalAsync(string ticket, CancellationToken ct = default)
        => throw new InvalidOperationException(DisabledMessage);

    public Task<ServiceResponse<WireGuardKeyPairDto>> GenerateWireGuardKeyPairAsync(CancellationToken ct = default)
        => Task.FromResult(Disabled<WireGuardKeyPairDto>());

    public Task<ServiceResponse<WireGuardPskDto>> GenerateWireGuardPskAsync(CancellationToken ct = default)
        => Task.FromResult(Disabled<WireGuardPskDto>());

    public Task<ServiceResponse<NftApplyResultDto>> ApplyWireGuardAsync(CancellationToken ct = default)
        => Task.FromResult(Disabled<NftApplyResultDto>());

    public Task<ServiceResponse<NftApplyResultDto>> StopWireGuardAsync(CancellationToken ct = default)
        => Task.FromResult(Disabled<NftApplyResultDto>());

    public Task<ServiceResponse<NetworkApplyResult>> ApplyDnsAsync(DnsForwarderConfig config, CancellationToken ct = default)
        => Task.FromResult(Disabled<NetworkApplyResult>());

    public Task<ServiceResponse<IReadOnlyList<WgPeerLiveStatus>>> GetWireGuardStatusAsync(CancellationToken ct = default)
        => Task.FromResult(ServiceResponse<IReadOnlyList<WgPeerLiveStatus>>.Ok(
            Array.Empty<WgPeerLiveStatus>(), "Daemon disabled — no live status available."));

    public Task<ServiceResponse<IReadOnlyList<string>>> ListWireGuardImportablesAsync(CancellationToken ct = default)
        => Task.FromResult(ServiceResponse<IReadOnlyList<string>>.Ok(Array.Empty<string>(), "Daemon disabled."));

    public Task<ServiceResponse<NetFirewall.Services.Vpn.WireGuardImportResult>> ImportWireGuardConfigAsync(string interfaceName, CancellationToken ct = default)
        => Task.FromResult(Disabled<NetFirewall.Services.Vpn.WireGuardImportResult>());

    public Task<ServiceResponse<IReadOnlyList<NetFirewall.Services.Monitoring.ServiceHealth>>> GetSystemServicesAsync(CancellationToken ct = default)
        => Task.FromResult(ServiceResponse<IReadOnlyList<NetFirewall.Services.Monitoring.ServiceHealth>>.Ok(
            Array.Empty<NetFirewall.Services.Monitoring.ServiceHealth>(), "Daemon disabled."));

    public Task<ServiceResponse<IReadOnlyList<NetFirewall.Services.Monitoring.WanReachability>>> GetWanStatusAsync(CancellationToken ct = default)
        => Task.FromResult(ServiceResponse<IReadOnlyList<NetFirewall.Services.Monitoring.WanReachability>>.Ok(
            Array.Empty<NetFirewall.Services.Monitoring.WanReachability>(), "Daemon disabled."));

    public Task<ServiceResponse<IReadOnlyList<NetFirewall.Services.Firewall.PendingChangesSummary>>> GetPendingChangesAsync(CancellationToken ct = default)
        => Task.FromResult(ServiceResponse<IReadOnlyList<NetFirewall.Services.Firewall.PendingChangesSummary>>.Ok(
            Array.Empty<NetFirewall.Services.Firewall.PendingChangesSummary>(), "Daemon disabled."));

    public Task<ServiceResponse<IReadOnlyList<NetFirewall.Services.Firewall.ApplyHistoryEntry>>> GetApplyHistoryAsync(int limit = 10, CancellationToken ct = default)
        => Task.FromResult(ServiceResponse<IReadOnlyList<NetFirewall.Services.Firewall.ApplyHistoryEntry>>.Ok(
            Array.Empty<NetFirewall.Services.Firewall.ApplyHistoryEntry>(), "Daemon disabled."));

    public Task<ServiceResponse<NetFirewall.Services.Firewall.PolicyRoutingApplyResult>> ApplyPolicyRoutingAsync(bool dryRun, CancellationToken ct = default)
        => Task.FromResult(Disabled<NetFirewall.Services.Firewall.PolicyRoutingApplyResult>());

    public Task<ServiceResponse<TopTalkersDto>> GetTopTalkersAsync(int hours = 24, int limit = 5, CancellationToken ct = default)
        => Task.FromResult(ServiceResponse<TopTalkersDto>.Ok(
            new TopTalkersDto(Array.Empty<NetFirewall.Services.Monitoring.TopTalkerHost>(),
                              Array.Empty<NetFirewall.Services.Monitoring.TopTalkerService>()),
            "Daemon disabled."));

    public Task<ServiceResponse<HostDestinationsDto>> GetHostDestinationsAsync(
        string srcIp, int hours = 24, int limit = 10, CancellationToken ct = default)
        => Task.FromResult(ServiceResponse<HostDestinationsDto>.Ok(
            new HostDestinationsDto(
                System.Net.IPAddress.TryParse(srcIp, out var ip) ? ip : System.Net.IPAddress.None,
                Array.Empty<NetFirewall.Services.Monitoring.TopTalkerDestination>()),
            "Daemon disabled."));

    public Task<ServiceResponse<TopDestinationsDto>> GetTopDestinationsAsync(
        int hours = 24, int limit = 8, CancellationToken ct = default)
        => Task.FromResult(ServiceResponse<TopDestinationsDto>.Ok(
            new TopDestinationsDto(Array.Empty<NetFirewall.Services.Monitoring.TopTalkerDestination>()),
            "Daemon disabled."));

    public Task<ServiceResponse<WanHealthDto>> GetWanHealthAsync(CancellationToken ct = default)
        => Task.FromResult(ServiceResponse<WanHealthDto>.Ok(
            new WanHealthDto(Array.Empty<NetFirewall.Models.WanMonitor.WanHealthState>(),
                             Array.Empty<NetFirewall.Models.WanMonitor.WanHealthEvent>()),
            "Daemon disabled."));

    public Task<ServiceResponse<VpnHealthDto>> GetVpnHealthAsync(CancellationToken ct = default)
        => Task.FromResult(ServiceResponse<VpnHealthDto>.Ok(
            new VpnHealthDto(Array.Empty<NetFirewall.Models.Vpn.VpnHealthState>(),
                             Array.Empty<NetFirewall.Models.Vpn.VpnHealthEvent>(),
                             Array.Empty<NetFirewall.Models.Vpn.SystemAlert>()),
            "Daemon disabled."));
}
