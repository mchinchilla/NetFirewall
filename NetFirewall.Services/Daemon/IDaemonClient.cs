using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.System;

namespace NetFirewall.Services.Daemon;

/// <summary>
/// Tiny client-side surface over the daemon's HTTP-on-Unix-socket API.
/// All calls forward the current user's session token via the configured header
/// so the daemon can authenticate the request against <c>user_sessions</c>.
/// </summary>
public interface IDaemonClient
{
    /// <summary><c>GET /v1/network/interfaces</c> — list configured interfaces (read-only).</summary>
    Task<ServiceResponse<IReadOnlyList<FwInterface>>> ListInterfacesAsync(CancellationToken ct = default);

    /// <summary><c>GET /v1/network/interfaces/discover</c> — physical NICs with type/role suggestions (read-only).</summary>
    Task<ServiceResponse<IReadOnlyList<InterfaceSuggestion>>> DiscoverInterfacesAsync(CancellationToken ct = default);

    /// <summary>
    /// <c>POST /v1/network/interfaces/redetect</c> — reconcile <c>fw_interfaces</c>
    /// against the live OS. UPSERTs ip/mask/gateway/mac/mtu from /sys/class/net,
    /// preserving operator-edited fields. Idempotent.
    /// </summary>
    Task<ServiceResponse<RedetectResult>> RedetectInterfacesAsync(CancellationToken ct = default);

    /// <summary><c>POST /v1/network/interfaces</c> — create a new interface row. Elevation required.</summary>
    Task<ServiceResponse<FwInterface>> CreateInterfaceAsync(FwInterface iface, CancellationToken ct = default);

    /// <summary><c>PUT /v1/network/interfaces/{id}</c> — update IP / mask / gateway / MAC etc. Elevation required.</summary>
    Task<ServiceResponse<FwInterface>> UpdateInterfaceAsync(Guid id, FwInterface iface, CancellationToken ct = default);

    /// <summary><c>POST /v1/network/{id}/apply</c></summary>
    Task<ServiceResponse<NetworkApplyResult>> ApplyInterfaceAsync(Guid interfaceId, CancellationToken ct = default);

    /// <summary><c>POST /v1/network/restart</c></summary>
    Task<ServiceResponse<NetworkApplyResult>> RestartNetworkingAsync(CancellationToken ct = default);

    /// <summary><c>POST /v1/routes/{id}/apply</c></summary>
    Task<ServiceResponse<NetworkApplyResult>> ApplyRouteAsync(Guid routeId, CancellationToken ct = default);

    /// <summary><c>POST /v1/routes/{id}/remove</c></summary>
    Task<ServiceResponse<NetworkApplyResult>> RemoveRouteAsync(Guid routeId, CancellationToken ct = default);

    /// <summary><c>POST /v1/firewall/apply</c> — generate nftables.conf and run <c>nft -f</c>.</summary>
    Task<ServiceResponse<NftApplyResultDto>> ApplyFirewallAsync(CancellationToken ct = default);

    /// <summary><c>POST /v1/firewall/apply-qos</c> — generate the tc/HTB script and execute it via bash.</summary>
    Task<ServiceResponse<NftApplyResultDto>> ApplyQosAsync(CancellationToken ct = default);

    /// <summary><c>GET /v1/firewall/current-ruleset</c> — read live <c>nft list ruleset</c>.</summary>
    Task<string?> GetCurrentRulesetAsync(CancellationToken ct = default);

    /// <summary>Lightweight health probe (no auth on the daemon side).</summary>
    Task<bool> IsAliveAsync(CancellationToken ct = default);

    /// <summary>
    /// <c>POST /v1/auth/login</c> — single-step login for headless clients (TUI).
    /// Validates username + password + TOTP / recovery code, returns the issued
    /// session token in the envelope. Caller stores it in their
    /// <see cref="IDaemonSessionTokenProvider"/> and subsequent calls forward it.
    /// </summary>
    Task<ServiceResponse<TuiLoginResult>> LoginAsync(TuiLoginRequest request, CancellationToken ct = default);

    /// <summary>
    /// <c>POST /v1/auth/logout</c> — revokes the current session on the daemon
    /// side. Caller should also clear the local token after a successful response.
    /// </summary>
    Task<ServiceResponse<bool>> LogoutAsync(CancellationToken ct = default);

    /// <summary>
    /// <c>GET /v1/auth/recovery/users</c> — list all users (slim view) so the
    /// recovery picker can render. Root-peer only; no session required.
    /// </summary>
    Task<ServiceResponse<IReadOnlyList<RecoveryUserSummary>>> ListUsersForRecoveryAsync(CancellationToken ct = default);

    /// <summary>
    /// <c>POST /v1/auth/recovery/reset-password</c> — set a new password and
    /// clear lockout for the named user. Root-peer only.
    /// </summary>
    Task<ServiceResponse<RecoveryActionResult>> RecoveryResetPasswordAsync(string username, string newPassword, CancellationToken ct = default);

    /// <summary>
    /// <c>POST /v1/auth/recovery/disable-totp</c> — wipe the user's TOTP secret
    /// (forcing re-enroll on next Web login) and clear lockout. Root-peer only.
    /// </summary>
    Task<ServiceResponse<RecoveryActionResult>> RecoveryDisableTotpAsync(string username, CancellationToken ct = default);

    /// <summary><c>POST /v1/crypto/encrypt</c> — daemon holds the master key, returns ciphertext.</summary>
    Task<byte[]> EncryptTotpAsync(byte[] plaintext, CancellationToken ct = default);

    /// <summary><c>POST /v1/crypto/decrypt</c> — daemon holds the master key, returns plaintext. Throws on failure.</summary>
    Task<byte[]> DecryptTotpAsync(byte[] ciphertext, CancellationToken ct = default);

    /// <summary><c>POST /v1/wireguard/genkey</c> — returns a fresh X25519 keypair. Used when adding a new peer.</summary>
    Task<ServiceResponse<WireGuardKeyPairDto>> GenerateWireGuardKeyPairAsync(CancellationToken ct = default);

    /// <summary><c>POST /v1/wireguard/genpsk</c> — returns a fresh preshared key.</summary>
    Task<ServiceResponse<WireGuardPskDto>> GenerateWireGuardPskAsync(CancellationToken ct = default);

    /// <summary><c>POST /v1/wireguard/apply</c> — write wg0.conf and bring it up (or hot-reload via wg syncconf).</summary>
    Task<ServiceResponse<NftApplyResultDto>> ApplyWireGuardAsync(CancellationToken ct = default);

    /// <summary><c>POST /v1/wireguard/stop</c> — wg-quick down.</summary>
    Task<ServiceResponse<NftApplyResultDto>> StopWireGuardAsync(CancellationToken ct = default);

    /// <summary><c>GET /v1/wireguard/status</c> — wg show dump parsed into per-peer stats.</summary>
    Task<ServiceResponse<IReadOnlyList<NetFirewall.Models.Vpn.WgPeerLiveStatus>>> GetWireGuardStatusAsync(CancellationToken ct = default);

    /// <summary><c>GET /v1/wireguard/import</c> — list wg-quick .conf files on disk.</summary>
    Task<ServiceResponse<IReadOnlyList<string>>> ListWireGuardImportablesAsync(CancellationToken ct = default);

    /// <summary>
    /// <c>POST /v1/wireguard/import/{name}</c> — read /etc/wireguard/{name}.conf
    /// and upsert into wg_servers + wg_peers. Idempotent. Elevation required.
    /// </summary>
    Task<ServiceResponse<NetFirewall.Services.Vpn.WireGuardImportResult>> ImportWireGuardConfigAsync(string interfaceName, CancellationToken ct = default);

    /// <summary><c>GET /v1/system/services</c> — systemd unit status for the dashboard.</summary>
    Task<ServiceResponse<IReadOnlyList<NetFirewall.Services.Monitoring.ServiceHealth>>> GetSystemServicesAsync(CancellationToken ct = default);

    /// <summary><c>GET /v1/system/wan-status</c> — ping each WAN gateway, return up/down + RTT.</summary>
    Task<ServiceResponse<IReadOnlyList<NetFirewall.Services.Monitoring.WanReachability>>> GetWanStatusAsync(CancellationToken ct = default);

    /// <summary><c>GET /v1/system/pending-changes</c> — DB rows changed since last Apply, per kind.</summary>
    Task<ServiceResponse<IReadOnlyList<NetFirewall.Services.Firewall.PendingChangesSummary>>> GetPendingChangesAsync(CancellationToken ct = default);

    /// <summary><c>GET /v1/system/apply-history</c> — last N apply attempts.</summary>
    Task<ServiceResponse<IReadOnlyList<NetFirewall.Services.Firewall.ApplyHistoryEntry>>> GetApplyHistoryAsync(int limit = 10, CancellationToken ct = default);

    /// <summary><c>POST /v1/firewall/apply-policy-routing</c> — reconcile iproute2 with DB. Set <paramref name="dryRun"/> to preview without changes.</summary>
    Task<ServiceResponse<NetFirewall.Services.Firewall.PolicyRoutingApplyResult>> ApplyPolicyRoutingAsync(bool dryRun, CancellationToken ct = default);

    /// <summary><c>GET /v1/system/top-talkers</c> — top N LAN hosts + services by bytes in the last N hours.</summary>
    Task<ServiceResponse<TopTalkersDto>> GetTopTalkersAsync(int hours = 24, int limit = 5, CancellationToken ct = default);

    /// <summary><c>GET /v1/system/wan-health</c> — per-WAN health state + recent transition events.</summary>
    Task<ServiceResponse<WanHealthDto>> GetWanHealthAsync(CancellationToken ct = default);
}

public sealed record WireGuardKeyPairDto(string PrivateKey, string PublicKey);
public sealed record WireGuardPskDto(string PresharedKey);

public sealed record NftApplyResultDto(int ExitCode, string? BackupPath, string? Output, string? Error);

/// <summary>
/// Wire shape of the top-talkers endpoint. Hosts and services are independent
/// lists — the dashboard shows both side-by-side.
/// </summary>
public sealed record TopTalkersDto(
    IReadOnlyList<NetFirewall.Services.Monitoring.TopTalkerHost> Hosts,
    IReadOnlyList<NetFirewall.Services.Monitoring.TopTalkerService> Services);

public sealed record WanHealthDto(
    IReadOnlyList<NetFirewall.Models.WanMonitor.WanHealthState> State,
    IReadOnlyList<NetFirewall.Models.WanMonitor.WanHealthEvent> RecentEvents);
