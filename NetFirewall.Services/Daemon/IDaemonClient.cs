using System.Net.WebSockets;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.Network;
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

    /// <summary>
    /// <c>POST /v1/terminal/open</c> — admin + fresh TOTP. Returns a one-time attach
    /// ticket (in the envelope's <c>Data</c>) bound to the current session.
    /// </summary>
    Task<ServiceResponse<TerminalTicketDto>> OpenTerminalAsync(string totpCode, CancellationToken ct = default);

    /// <summary>
    /// <c>GET /v1/terminal/attach</c> (WebSocket) — opens a raw byte stream to a
    /// freshly-spawned root PTY, authenticated by the session header + the one-time
    /// <paramref name="ticket"/>. The caller pumps bytes between this socket and the
    /// browser. The returned <see cref="WebSocket"/> is owned by the caller (dispose it).
    /// </summary>
    Task<WebSocket> ConnectTerminalAsync(string ticket, CancellationToken ct = default);

    /// <summary><c>POST /v1/wireguard/genkey</c> — returns a fresh X25519 keypair. Used when adding a new peer.</summary>
    Task<ServiceResponse<WireGuardKeyPairDto>> GenerateWireGuardKeyPairAsync(CancellationToken ct = default);

    /// <summary><c>POST /v1/wireguard/genpsk</c> — returns a fresh preshared key.</summary>
    Task<ServiceResponse<WireGuardPskDto>> GenerateWireGuardPskAsync(CancellationToken ct = default);

    /// <summary><c>POST /v1/wireguard/apply</c> — write wg0.conf and bring it up (or hot-reload via wg syncconf).</summary>
    Task<ServiceResponse<NftApplyResultDto>> ApplyWireGuardAsync(CancellationToken ct = default);

    /// <summary><c>POST /v1/wireguard/stop</c> — wg-quick down.</summary>
    Task<ServiceResponse<NftApplyResultDto>> StopWireGuardAsync(CancellationToken ct = default);

    /// <summary>
    /// <c>POST /v1/dns/apply</c> — render <c>/etc/unbound/unbound.conf.d/netfirewall.conf</c>
    /// from <paramref name="config"/> and restart unbound. Elevation required.
    /// </summary>
    Task<ServiceResponse<NetworkApplyResult>> ApplyDnsAsync(DnsForwarderConfig config, CancellationToken ct = default);

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

    // ───────────── Diagnostics (daemon-executed tools — docs/diagnostics.md) ─────────────
    // Runs come back as DiagRunEnvelope<T>: the diag_runs row id, timing, the verdict
    // status (ok/warn/fail = the tool ran; error/timeout/busy = it did not) and the result.

    /// <summary><c>POST /v1/diagnostics/ping</c> — ICMP probe steered by fwmark or interface.</summary>
    Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.PingResult>>> RunPingAsync(NetFirewall.Models.Diagnostics.PingRequest request, CancellationToken ct = default);

    /// <summary><c>POST /v1/diagnostics/traceroute</c>.</summary>
    Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.TracerouteResult>>> RunTracerouteAsync(NetFirewall.Models.Diagnostics.TracerouteRequest request, CancellationToken ct = default);

    /// <summary><c>POST /v1/diagnostics/route-get</c> — <c>ip route get</c> with mark/from/iif.</summary>
    Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.RouteGetResult>>> RunRouteGetAsync(NetFirewall.Models.Diagnostics.RouteGetRequest request, CancellationToken ct = default);

    /// <summary><c>POST /v1/diagnostics/conntrack</c> — filtered <c>conntrack -L</c>.</summary>
    Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.ConntrackLookupResult>>> RunConntrackLookupAsync(NetFirewall.Models.Diagnostics.ConntrackLookupRequest request, CancellationToken ct = default);

    /// <summary><c>POST /v1/diagnostics/drop-log</c> — kernel-journal nflog/martian explorer.</summary>
    Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.DropLogResult>>> RunDropLogAsync(NetFirewall.Models.Diagnostics.DropLogRequest request, CancellationToken ct = default);

    /// <summary><c>GET /v1/diagnostics/interfaces/health</c> — live link health, not persisted.</summary>
    Task<ServiceResponse<IReadOnlyList<NetFirewall.Models.Diagnostics.InterfaceHealth>>> GetInterfaceHealthAsync(CancellationToken ct = default);

    /// <summary><c>GET /v1/diagnostics/neighbors?iface=</c>.</summary>
    Task<ServiceResponse<IReadOnlyList<NetFirewall.Models.Diagnostics.NeighborEntry>>> GetNeighborsAsync(string? iface = null, CancellationToken ct = default);

    /// <summary><c>GET /v1/diagnostics/sysctl?iface=</c> — forwarding / rp_filter / martians / conntrack headroom.</summary>
    Task<ServiceResponse<IReadOnlyList<NetFirewall.Models.Diagnostics.DiagCheck>>> GetSysctlSanityAsync(string? iface = null, CancellationToken ct = default);

    /// <summary><c>POST /v1/diagnostics/vpn/doctor</c> — the full tunnel checklist.</summary>
    Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.DiagReport>>> RunVpnDoctorAsync(NetFirewall.Models.Diagnostics.VpnDoctorRequest request, CancellationToken ct = default);

    /// <summary><c>POST /v1/diagnostics/vpn/probe</c> — ping through the tunnel and read the transfer counters.</summary>
    Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.VpnProbeResult>>> RunVpnProbeAsync(NetFirewall.Models.Diagnostics.VpnProbeRequest request, CancellationToken ct = default);

    /// <summary><c>POST /v1/diagnostics/vpn/compare</c> — diff a pasted wg-quick config against what we run.</summary>
    Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.VpnCompareResult>>> RunVpnCompareAsync(NetFirewall.Models.Diagnostics.VpnCompareRequest request, CancellationToken ct = default);

    // ── Invasive diagnostics (Admin + elevated): start returns a job id to poll. ──

    /// <summary><c>POST /v1/diagnostics/trace/start</c> — temporary nftrace table + <c>nft monitor trace</c>.</summary>
    Task<ServiceResponse<Guid>> StartTraceAsync(NetFirewall.Models.Diagnostics.TraceRequest request, CancellationToken ct = default);

    /// <summary><c>POST /v1/diagnostics/capture/start</c> — bounded tcpdump to a pcap file.</summary>
    Task<ServiceResponse<Guid>> StartCaptureAsync(NetFirewall.Models.Diagnostics.CaptureRequest request, CancellationToken ct = default);

    /// <summary><c>GET /v1/diagnostics/jobs/{id}</c> — poll a running or finished job.</summary>
    Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagJobSnapshot>> GetDiagJobAsync(Guid id, CancellationToken ct = default);

    /// <summary><c>POST /v1/diagnostics/jobs/{id}/cancel</c> — stop early, keeping the partial result.</summary>
    Task<ServiceResponse<object>> CancelDiagJobAsync(Guid id, CancellationToken ct = default);

    /// <summary>
    /// <c>GET /v1/diagnostics/capture/{id}/download</c> — the pcap as a stream the Web
    /// can pipe straight to the browser. Null when the file is gone. The caller owns the stream.
    /// </summary>
    Task<Stream?> DownloadCaptureAsync(Guid id, CancellationToken ct = default);

    /// <summary><c>DELETE /v1/diagnostics/capture/{id}</c>.</summary>
    Task<ServiceResponse<object>> DeleteCaptureAsync(Guid id, CancellationToken ct = default);

    /// <summary><c>POST /v1/diagnostics/wan/doctor</c> — uplinks, failover config/state, per-WAN routing and reachability.</summary>
    Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.DiagReport>>> RunWanDoctorAsync(CancellationToken ct = default);

    /// <summary><c>POST /v1/diagnostics/dhcp/doctor</c> — unit, listener, scopes, pool pressure, recent leases, firewall.</summary>
    Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.DiagReport>>> RunDhcpDoctorAsync(CancellationToken ct = default);

    /// <summary><c>POST /v1/diagnostics/dns/doctor</c> — resolver unit, listeners, local and LAN-facing resolution, upstreams.</summary>
    Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.DiagReport>>> RunDnsDoctorAsync(CancellationToken ct = default);

    /// <summary><c>GET /v1/system/top-talkers</c> — top N LAN hosts + services by bytes in the last N hours.</summary>
    Task<ServiceResponse<TopTalkersDto>> GetTopTalkersAsync(int hours = 24, int limit = 5, CancellationToken ct = default);

    /// <summary><c>GET /v1/system/top-talkers/host/{srcIp}/destinations</c> — per-destination
    /// drill-down for one LAN host, enriched with ASN/org.</summary>
    Task<ServiceResponse<HostDestinationsDto>> GetHostDestinationsAsync(
        string srcIp, int hours = 24, int limit = 10, CancellationToken ct = default);

    /// <summary><c>GET /v1/system/top-destinations</c> — busiest destinations across
    /// the whole LAN, ASN-enriched. Powers the home dashboard panel.</summary>
    Task<ServiceResponse<TopDestinationsDto>> GetTopDestinationsAsync(
        int hours = 24, int limit = 8, CancellationToken ct = default);

    /// <summary><c>GET /v1/system/wan-health</c> — per-WAN health state + recent transition events.</summary>
    Task<ServiceResponse<WanHealthDto>> GetWanHealthAsync(CancellationToken ct = default);

    /// <summary><c>POST /v1/system/wan-failover</c> — manually pin a WAN as the active
    /// default route (sticky override). Elevated.</summary>
    Task<ServiceResponse<bool>> ForceWanFailoverAsync(Guid interfaceId, CancellationToken ct = default);

    /// <summary><c>POST /v1/system/wan-failover/clear</c> — drop the manual override,
    /// return to automatic priority-based failover. Elevated.</summary>
    Task<ServiceResponse<bool>> ClearWanFailoverOverrideAsync(CancellationToken ct = default);

    /// <summary><c>GET /v1/system/vpn-health</c> — per-peer WireGuard health state, recent
    /// transitions, and active UI alerts.</summary>
    Task<ServiceResponse<VpnHealthDto>> GetVpnHealthAsync(CancellationToken ct = default);

    /// <summary><c>GET /v1/system/alerts</c> — recent system alerts (active + resolved),
    /// the unified activity feed. Powers the notifications dropdown + history page.</summary>
    Task<ServiceResponse<AlertsDto>> GetRecentAlertsAsync(int limit = 50, CancellationToken ct = default);
}

public sealed record TerminalTicketDto(string Ticket);

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

/// <summary>Wire shape of the per-host destination drill-down.</summary>
public sealed record HostDestinationsDto(
    System.Net.IPAddress SrcIp,
    IReadOnlyList<NetFirewall.Services.Monitoring.TopTalkerDestination> Destinations);

/// <summary>Wire shape of the LAN-wide top-destinations panel.</summary>
public sealed record TopDestinationsDto(
    IReadOnlyList<NetFirewall.Services.Monitoring.TopTalkerDestination> Destinations);

public sealed record WanHealthDto(
    IReadOnlyList<NetFirewall.Models.WanMonitor.WanHealthState> State,
    IReadOnlyList<NetFirewall.Models.WanMonitor.WanHealthEvent> RecentEvents,
    NetFirewall.Models.WanMonitor.WanFailoverControl Control);

public sealed record VpnHealthDto(
    IReadOnlyList<NetFirewall.Models.Vpn.VpnHealthState> State,
    IReadOnlyList<NetFirewall.Models.Vpn.VpnHealthEvent> RecentEvents,
    IReadOnlyList<NetFirewall.Models.Vpn.SystemAlert> ActiveAlerts);

public sealed record AlertsDto(
    IReadOnlyList<NetFirewall.Models.Vpn.SystemAlert> Alerts);
