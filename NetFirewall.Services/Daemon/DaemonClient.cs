using System.Net.Http.Json;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.Network;
using NetFirewall.Models.System;

namespace NetFirewall.Services.Daemon;

public sealed class DaemonClient : IDaemonClient, IDisposable
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web)
    {
        // IPAddress has no built-in System.Text.Json converter — without this,
        // any DTO carrying IPAddress (TopTalkerHost.SrcIp, etc.) deserializes
        // the field as null and downstream .ToString() / projection silently
        // breaks the dashboard panel.
        Converters = { new Json.IPAddressJsonConverter() },
    };

    private readonly HttpClient _http;
    private readonly SocketsHttpHandler _handler; // shared by _http AND the terminal ClientWebSocket
    private readonly DaemonClientOptions _opts;
    private readonly IDaemonSessionTokenProvider _tokenProvider;
    private readonly ILogger<DaemonClient> _logger;
    private bool _disposed;

    public DaemonClient(
        IOptions<DaemonClientOptions> opts,
        IDaemonSessionTokenProvider tokenProvider,
        ILogger<DaemonClient> logger)
    {
        _opts = opts.Value;
        _tokenProvider = tokenProvider;
        _logger = logger;

        var socketPath = ResolveSocketPath(_opts.SocketPath);
        _handler = new SocketsHttpHandler
        {
            ConnectCallback = async (ctx, ct) =>
            {
                var s = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                await s.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), ct);
                return new NetworkStream(s, ownsSocket: true);
            }
        };
        _http = new HttpClient(_handler)
        {
            // The Host header is irrelevant over a Unix socket but required by Kestrel.
            BaseAddress = new Uri("http://daemon"),
            Timeout = _opts.Timeout
        };
    }

    public Task<ServiceResponse<IReadOnlyList<FwInterface>>> ListInterfacesAsync(CancellationToken ct = default)
        => GetAsync<IReadOnlyList<FwInterface>>("/v1/network/interfaces", ct);

    public Task<ServiceResponse<IReadOnlyList<InterfaceSuggestion>>> DiscoverInterfacesAsync(CancellationToken ct = default)
        => GetAsync<IReadOnlyList<InterfaceSuggestion>>("/v1/network/interfaces/discover", ct);

    public Task<ServiceResponse<RedetectResult>> RedetectInterfacesAsync(CancellationToken ct = default)
        => PostAsync<RedetectResult>("/v1/network/interfaces/redetect", ct);

    public Task<ServiceResponse<FwInterface>> CreateInterfaceAsync(FwInterface iface, CancellationToken ct = default)
        => PostJsonAsync<FwInterface, FwInterface>("/v1/network/interfaces", iface, ct);

    public Task<ServiceResponse<FwInterface>> UpdateInterfaceAsync(Guid id, FwInterface iface, CancellationToken ct = default)
        => SendJsonAsync<FwInterface, FwInterface>(HttpMethod.Put, $"/v1/network/interfaces/{id}", iface, ct);

    public Task<ServiceResponse<NetworkApplyResult>> ApplyInterfaceAsync(Guid id, CancellationToken ct = default)
        => PostAsync<NetworkApplyResult>($"/v1/network/{id}/apply", ct);

    public Task<ServiceResponse<NetworkApplyResult>> RestartNetworkingAsync(CancellationToken ct = default)
        => PostAsync<NetworkApplyResult>("/v1/network/restart", ct);

    public Task<ServiceResponse<NetworkApplyResult>> ApplyRouteAsync(Guid id, CancellationToken ct = default)
        => PostAsync<NetworkApplyResult>($"/v1/routes/{id}/apply", ct);

    public Task<ServiceResponse<NetworkApplyResult>> RemoveRouteAsync(Guid id, CancellationToken ct = default)
        => PostAsync<NetworkApplyResult>($"/v1/routes/{id}/remove", ct);

    public Task<ServiceResponse<NftApplyResultDto>> ApplyFirewallAsync(CancellationToken ct = default)
        => PostAsync<NftApplyResultDto>("/v1/firewall/apply", ct);

    public Task<ServiceResponse<NftApplyResultDto>> ApplyQosAsync(CancellationToken ct = default)
        => PostAsync<NftApplyResultDto>("/v1/firewall/apply-qos", ct);

    public async Task<string?> GetCurrentRulesetAsync(CancellationToken ct = default)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Get, "/v1/firewall/current-ruleset");
            AttachSessionHeader(req);
            using var resp = await _http.SendAsync(req, ct);
            return resp.IsSuccessStatusCode ? await resp.Content.ReadAsStringAsync(ct) : null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not fetch current nft ruleset from daemon");
            return null;
        }
    }

    public async Task<bool> IsAliveAsync(CancellationToken ct = default)
    {
        try
        {
            using var resp = await _http.GetAsync("/health", ct);
            return resp.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Daemon health probe failed");
            return false;
        }
    }

    public async Task<ServiceResponse<TuiLoginResult>> LoginAsync(TuiLoginRequest request, CancellationToken ct = default)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/auth/login")
            {
                Content = JsonContent.Create(request, options: JsonOpts)
            };
            // Login is anonymous on the daemon side — no header attach.
            using var resp = await _http.SendAsync(req, ct);
            return await ReadEnvelopeAsync<TuiLoginResult>(resp, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Daemon login call failed");
            return ServiceResponse<TuiLoginResult>.Fail($"Daemon unreachable: {ex.Message}");
        }
    }

    public async Task<ServiceResponse<bool>> LogoutAsync(CancellationToken ct = default)
    {
        try
        {
            using var req = new HttpRequestMessage(HttpMethod.Post, "/v1/auth/logout");
            AttachSessionHeader(req);
            using var resp = await _http.SendAsync(req, ct);
            return await ReadEnvelopeAsync<bool>(resp, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Daemon logout call failed");
            return ServiceResponse<bool>.Fail($"Daemon unreachable: {ex.Message}");
        }
    }

    public Task<ServiceResponse<IReadOnlyList<RecoveryUserSummary>>> ListUsersForRecoveryAsync(CancellationToken ct = default)
        => GetAsync<IReadOnlyList<RecoveryUserSummary>>("/v1/auth/recovery/users", ct);

    public Task<ServiceResponse<RecoveryActionResult>> RecoveryResetPasswordAsync(string username, string newPassword, CancellationToken ct = default)
        => PostJsonAsync<RecoveryResetPasswordRequest, RecoveryActionResult>(
            "/v1/auth/recovery/reset-password",
            new RecoveryResetPasswordRequest(username, newPassword),
            ct);

    public Task<ServiceResponse<RecoveryActionResult>> RecoveryDisableTotpAsync(string username, CancellationToken ct = default)
        => PostJsonAsync<RecoveryDisableTotpRequest, RecoveryActionResult>(
            "/v1/auth/recovery/disable-totp",
            new RecoveryDisableTotpRequest(username),
            ct);

    public async Task<byte[]> EncryptTotpAsync(byte[] plaintext, CancellationToken ct = default)
        => await CryptoCallAsync("/v1/crypto/encrypt", plaintext, ct);

    public async Task<byte[]> DecryptTotpAsync(byte[] ciphertext, CancellationToken ct = default)
        => await CryptoCallAsync("/v1/crypto/decrypt", ciphertext, ct);

    public Task<ServiceResponse<WireGuardKeyPairDto>> GenerateWireGuardKeyPairAsync(CancellationToken ct = default)
        => PostAsync<WireGuardKeyPairDto>("/v1/wireguard/genkey", ct);

    public Task<ServiceResponse<WireGuardPskDto>> GenerateWireGuardPskAsync(CancellationToken ct = default)
        => PostAsync<WireGuardPskDto>("/v1/wireguard/genpsk", ct);

    public Task<ServiceResponse<NftApplyResultDto>> ApplyWireGuardAsync(CancellationToken ct = default)
        => PostAsync<NftApplyResultDto>("/v1/wireguard/apply", ct);

    public Task<ServiceResponse<NftApplyResultDto>> StopWireGuardAsync(CancellationToken ct = default)
        => PostAsync<NftApplyResultDto>("/v1/wireguard/stop", ct);

    public Task<ServiceResponse<NetworkApplyResult>> ApplyDnsAsync(DnsForwarderConfig config, CancellationToken ct = default)
        => PostJsonAsync<DnsForwarderConfig, NetworkApplyResult>("/v1/dns/apply", config, ct);

    public async Task<ServiceResponse<IReadOnlyList<NetFirewall.Models.Vpn.WgPeerLiveStatus>>> GetWireGuardStatusAsync(CancellationToken ct = default)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, "/v1/wireguard/status");
        AttachSessionHeader(req);
        try
        {
            using var resp = await _http.SendAsync(req, ct);
            return await ReadEnvelopeAsync<IReadOnlyList<NetFirewall.Models.Vpn.WgPeerLiveStatus>>(resp, ct);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "WireGuard status fetch failed");
            return ServiceResponse<IReadOnlyList<NetFirewall.Models.Vpn.WgPeerLiveStatus>>.Fail($"Daemon unreachable: {ex.Message}");
        }
    }

    public Task<ServiceResponse<IReadOnlyList<string>>> ListWireGuardImportablesAsync(CancellationToken ct = default)
        => GetAsync<IReadOnlyList<string>>("/v1/wireguard/import", ct);

    public Task<ServiceResponse<NetFirewall.Services.Vpn.WireGuardImportResult>> ImportWireGuardConfigAsync(string interfaceName, CancellationToken ct = default)
        => PostAsync<NetFirewall.Services.Vpn.WireGuardImportResult>($"/v1/wireguard/import/{Uri.EscapeDataString(interfaceName)}", ct);

    public Task<ServiceResponse<IReadOnlyList<NetFirewall.Services.Monitoring.ServiceHealth>>> GetSystemServicesAsync(CancellationToken ct = default)
        => GetAsync<IReadOnlyList<NetFirewall.Services.Monitoring.ServiceHealth>>("/v1/system/services", ct);

    public Task<ServiceResponse<IReadOnlyList<NetFirewall.Services.Monitoring.WanReachability>>> GetWanStatusAsync(CancellationToken ct = default)
        => GetAsync<IReadOnlyList<NetFirewall.Services.Monitoring.WanReachability>>("/v1/system/wan-status", ct);

    public Task<ServiceResponse<IReadOnlyList<NetFirewall.Services.Firewall.PendingChangesSummary>>> GetPendingChangesAsync(CancellationToken ct = default)
        => GetAsync<IReadOnlyList<NetFirewall.Services.Firewall.PendingChangesSummary>>("/v1/system/pending-changes", ct);

    public Task<ServiceResponse<IReadOnlyList<NetFirewall.Services.Firewall.ApplyHistoryEntry>>> GetApplyHistoryAsync(int limit = 10, CancellationToken ct = default)
        => GetAsync<IReadOnlyList<NetFirewall.Services.Firewall.ApplyHistoryEntry>>($"/v1/system/apply-history?limit={limit}", ct);

    public Task<ServiceResponse<NetFirewall.Services.Firewall.PolicyRoutingApplyResult>> ApplyPolicyRoutingAsync(bool dryRun, CancellationToken ct = default)
        => PostAsync<NetFirewall.Services.Firewall.PolicyRoutingApplyResult>(
            $"/v1/firewall/apply-policy-routing?dryRun={(dryRun ? "true" : "false")}", ct);

    // ───────────── Diagnostics ─────────────
    public Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.PingResult>>> RunPingAsync(NetFirewall.Models.Diagnostics.PingRequest request, CancellationToken ct = default)
        => PostJsonAsync<NetFirewall.Models.Diagnostics.PingRequest, NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.PingResult>>("/v1/diagnostics/ping", request, ct);

    public Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.TracerouteResult>>> RunTracerouteAsync(NetFirewall.Models.Diagnostics.TracerouteRequest request, CancellationToken ct = default)
        => PostJsonAsync<NetFirewall.Models.Diagnostics.TracerouteRequest, NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.TracerouteResult>>("/v1/diagnostics/traceroute", request, ct);

    public Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.RouteGetResult>>> RunRouteGetAsync(NetFirewall.Models.Diagnostics.RouteGetRequest request, CancellationToken ct = default)
        => PostJsonAsync<NetFirewall.Models.Diagnostics.RouteGetRequest, NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.RouteGetResult>>("/v1/diagnostics/route-get", request, ct);

    public Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.ConntrackLookupResult>>> RunConntrackLookupAsync(NetFirewall.Models.Diagnostics.ConntrackLookupRequest request, CancellationToken ct = default)
        => PostJsonAsync<NetFirewall.Models.Diagnostics.ConntrackLookupRequest, NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.ConntrackLookupResult>>("/v1/diagnostics/conntrack", request, ct);

    public Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.DropLogResult>>> RunDropLogAsync(NetFirewall.Models.Diagnostics.DropLogRequest request, CancellationToken ct = default)
        => PostJsonAsync<NetFirewall.Models.Diagnostics.DropLogRequest, NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.DropLogResult>>("/v1/diagnostics/drop-log", request, ct);

    public Task<ServiceResponse<IReadOnlyList<NetFirewall.Models.Diagnostics.InterfaceHealth>>> GetInterfaceHealthAsync(CancellationToken ct = default)
        => GetAsync<IReadOnlyList<NetFirewall.Models.Diagnostics.InterfaceHealth>>("/v1/diagnostics/interfaces/health", ct);

    public Task<ServiceResponse<IReadOnlyList<NetFirewall.Models.Diagnostics.NeighborEntry>>> GetNeighborsAsync(string? iface = null, CancellationToken ct = default)
        => GetAsync<IReadOnlyList<NetFirewall.Models.Diagnostics.NeighborEntry>>(
            "/v1/diagnostics/neighbors" + (string.IsNullOrEmpty(iface) ? string.Empty : "?iface=" + Uri.EscapeDataString(iface)), ct);

    public Task<ServiceResponse<IReadOnlyList<NetFirewall.Models.Diagnostics.DiagCheck>>> GetSysctlSanityAsync(string? iface = null, CancellationToken ct = default)
        => GetAsync<IReadOnlyList<NetFirewall.Models.Diagnostics.DiagCheck>>(
            "/v1/diagnostics/sysctl" + (string.IsNullOrEmpty(iface) ? string.Empty : "?iface=" + Uri.EscapeDataString(iface)), ct);

    public Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.DiagReport>>> RunVpnDoctorAsync(NetFirewall.Models.Diagnostics.VpnDoctorRequest request, CancellationToken ct = default)
        => PostJsonAsync<NetFirewall.Models.Diagnostics.VpnDoctorRequest, NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.DiagReport>>("/v1/diagnostics/vpn/doctor", request, ct);

    public Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.VpnProbeResult>>> RunVpnProbeAsync(NetFirewall.Models.Diagnostics.VpnProbeRequest request, CancellationToken ct = default)
        => PostJsonAsync<NetFirewall.Models.Diagnostics.VpnProbeRequest, NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.VpnProbeResult>>("/v1/diagnostics/vpn/probe", request, ct);

    public Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.VpnCompareResult>>> RunVpnCompareAsync(NetFirewall.Models.Diagnostics.VpnCompareRequest request, CancellationToken ct = default)
        => PostJsonAsync<NetFirewall.Models.Diagnostics.VpnCompareRequest, NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.VpnCompareResult>>("/v1/diagnostics/vpn/compare", request, ct);

    public Task<ServiceResponse<Guid>> StartTraceAsync(NetFirewall.Models.Diagnostics.TraceRequest request, CancellationToken ct = default)
        => PostJsonAsync<NetFirewall.Models.Diagnostics.TraceRequest, Guid>("/v1/diagnostics/trace/start", request, ct);

    public Task<ServiceResponse<Guid>> StartCaptureAsync(NetFirewall.Models.Diagnostics.CaptureRequest request, CancellationToken ct = default)
        => PostJsonAsync<NetFirewall.Models.Diagnostics.CaptureRequest, Guid>("/v1/diagnostics/capture/start", request, ct);

    public Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagJobSnapshot>> GetDiagJobAsync(Guid id, CancellationToken ct = default)
        => GetAsync<NetFirewall.Models.Diagnostics.DiagJobSnapshot>($"/v1/diagnostics/jobs/{id}", ct);

    public Task<ServiceResponse<object>> CancelDiagJobAsync(Guid id, CancellationToken ct = default)
        => PostAsync<object>($"/v1/diagnostics/jobs/{id}/cancel", ct);

    public async Task<Stream?> DownloadCaptureAsync(Guid id, CancellationToken ct = default)
    {
        // Headers-read so the pcap streams through instead of being buffered in the
        // Web's memory. The response is disposed when the returned stream is.
        var req = new HttpRequestMessage(HttpMethod.Get, $"/v1/diagnostics/capture/{id}/download");
        AttachSessionHeader(req);
        try
        {
            var resp = await _http.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!resp.IsSuccessStatusCode) { resp.Dispose(); return null; }
            return await resp.Content.ReadAsStreamAsync(ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Capture download {Id} failed", id);
            return null;
        }
    }

    public Task<ServiceResponse<object>> DeleteCaptureAsync(Guid id, CancellationToken ct = default)
        => SendJsonAsync<object, object>(HttpMethod.Delete, $"/v1/diagnostics/capture/{id}", new { }, ct);

    public Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.DiagReport>>> RunWanDoctorAsync(CancellationToken ct = default)
        => PostAsync<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.DiagReport>>("/v1/diagnostics/wan/doctor", ct);

    public Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.DiagReport>>> RunDhcpDoctorAsync(CancellationToken ct = default)
        => PostAsync<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.DiagReport>>("/v1/diagnostics/dhcp/doctor", ct);

    public Task<ServiceResponse<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.DiagReport>>> RunDnsDoctorAsync(CancellationToken ct = default)
        => PostAsync<NetFirewall.Models.Diagnostics.DiagRunEnvelope<NetFirewall.Models.Diagnostics.DiagReport>>("/v1/diagnostics/dns/doctor", ct);

    public Task<ServiceResponse<TopTalkersDto>> GetTopTalkersAsync(int hours = 24, int limit = 5, CancellationToken ct = default)
        => GetAsync<TopTalkersDto>($"/v1/system/top-talkers?hours={hours}&limit={limit}", ct);

    public Task<ServiceResponse<HostDestinationsDto>> GetHostDestinationsAsync(
        string srcIp, int hours = 24, int limit = 10, CancellationToken ct = default)
        => GetAsync<HostDestinationsDto>(
            $"/v1/system/top-talkers/host/{Uri.EscapeDataString(srcIp)}/destinations?hours={hours}&limit={limit}", ct);

    public Task<ServiceResponse<TopDestinationsDto>> GetTopDestinationsAsync(
        int hours = 24, int limit = 8, CancellationToken ct = default)
        => GetAsync<TopDestinationsDto>($"/v1/system/top-destinations?hours={hours}&limit={limit}", ct);

    public Task<ServiceResponse<WanHealthDto>> GetWanHealthAsync(CancellationToken ct = default)
        => GetAsync<WanHealthDto>("/v1/system/wan-health", ct);

    public Task<ServiceResponse<bool>> ForceWanFailoverAsync(Guid interfaceId, CancellationToken ct = default)
        => PostJsonAsync<object, bool>("/v1/system/wan-failover", new { interfaceId }, ct);

    public Task<ServiceResponse<bool>> ClearWanFailoverOverrideAsync(CancellationToken ct = default)
        => PostAsync<bool>("/v1/system/wan-failover/clear", ct);

    public Task<ServiceResponse<VpnHealthDto>> GetVpnHealthAsync(CancellationToken ct = default)
        => GetAsync<VpnHealthDto>("/v1/system/vpn-health", ct);

    public Task<ServiceResponse<AlertsDto>> GetRecentAlertsAsync(int limit = 50, CancellationToken ct = default)
        => GetAsync<AlertsDto>($"/v1/system/alerts?limit={limit}", ct);

    private async Task<byte[]> CryptoCallAsync(string path, byte[] data, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = JsonContent.Create(new { Data = Convert.ToBase64String(data) }, options: JsonOpts)
        };
        AttachSessionHeader(req);

        using var resp = await _http.SendAsync(req, ct);
        var envelope = await ReadEnvelopeAsync<CryptoCallResult>(resp, ct);
        if (!envelope.Success || envelope.Data is null || string.IsNullOrEmpty(envelope.Data.Data))
        {
            throw new InvalidOperationException(
                $"Daemon crypto call to {path} failed: {envelope.Message ?? "(no message)"}");
        }
        return Convert.FromBase64String(envelope.Data.Data);
    }

    private sealed record CryptoCallResult(string Data);

    // ---- Terminal (root PTY) ----------------------------------------------------

    public Task<ServiceResponse<TerminalTicketDto>> OpenTerminalAsync(string totpCode, CancellationToken ct = default)
        => PostJsonAsync<TerminalOpenBody, TerminalTicketDto>(
            "/v1/terminal/open", new TerminalOpenBody(totpCode), ct);

    public async Task<WebSocket> ConnectTerminalAsync(string ticket, CancellationToken ct = default)
    {
        // ClientWebSocket over the SAME Unix-socket handler the HttpClient uses
        // (validated in the Phase 3a spike). The session token authenticates the
        // upgrade; the one-time ticket (query string) authorizes the attach.
        var cws = new ClientWebSocket();
        var token = _tokenProvider.GetCurrentToken();
        if (!string.IsNullOrEmpty(token))
            cws.Options.SetRequestHeader(_opts.SessionHeader, token);

        var uri = new Uri($"ws://daemon/v1/terminal/attach?ticket={Uri.EscapeDataString(ticket)}");
        try
        {
            // Reuse the handler (not the HttpClient) via a lightweight invoker so the
            // UDS ConnectCallback is honored for the WS upgrade.
            await cws.ConnectAsync(uri, new HttpMessageInvoker(_handler, disposeHandler: false), ct);
            return cws;
        }
        catch
        {
            cws.Dispose();
            throw;
        }
    }

    private sealed record TerminalOpenBody(string Code);

    /// <summary>
    /// Send a POST, forward the current session token from the provider,
    /// and translate non-2xx responses into a meaningful <see cref="ServiceResponse{T}"/>.
    /// </summary>
    private async Task<ServiceResponse<T>> PostAsync<T>(string path, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, path);
        AttachSessionHeader(req);

        try
        {
            using var resp = await _http.SendAsync(req, ct);
            return await ReadEnvelopeAsync<T>(resp, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Daemon call to {Path} failed", path);
            return ServiceResponse<T>.Fail($"Daemon unreachable: {ex.Message}");
        }
    }

    /// <summary>GET that forwards the session header and parses ServiceResponse&lt;T&gt;.</summary>
    private async Task<ServiceResponse<T>> GetAsync<T>(string path, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, path);
        AttachSessionHeader(req);

        try
        {
            using var resp = await _http.SendAsync(req, ct);
            return await ReadEnvelopeAsync<T>(resp, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Daemon call to {Path} failed", path);
            return ServiceResponse<T>.Fail($"Daemon unreachable: {ex.Message}");
        }
    }

    /// <summary>POST with a JSON body — for CRUD endpoints that take a model.</summary>
    private Task<ServiceResponse<TResp>> PostJsonAsync<TBody, TResp>(string path, TBody body, CancellationToken ct)
        => SendJsonAsync<TBody, TResp>(HttpMethod.Post, path, body, ct);

    /// <summary>PUT/POST/PATCH with a JSON body. Used by CRUD endpoints (create/update).</summary>
    private async Task<ServiceResponse<TResp>> SendJsonAsync<TBody, TResp>(HttpMethod method, string path, TBody body, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(method, path)
        {
            Content = JsonContent.Create(body, options: JsonOpts)
        };
        AttachSessionHeader(req);

        try
        {
            using var resp = await _http.SendAsync(req, ct);
            return await ReadEnvelopeAsync<TResp>(resp, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Daemon call to {Path} failed", path);
            return ServiceResponse<TResp>.Fail($"Daemon unreachable: {ex.Message}");
        }
    }

    private void AttachSessionHeader(HttpRequestMessage req)
    {
        var token = _tokenProvider.GetCurrentToken();
        if (!string.IsNullOrEmpty(token))
        {
            req.Headers.TryAddWithoutValidation(_opts.SessionHeader, token);
        }
    }

    internal static async Task<ServiceResponse<T>> ReadEnvelopeAsync<T>(HttpResponseMessage resp, CancellationToken ct)
    {
        // Daemon's contract: a ServiceResponse<T> JSON envelope, Success=false
        // for operation failures. Most endpoints send it with 200; a few
        // (/firewall/apply) send the SAME envelope with 500 so a raw HTTP
        // client also sees the failure. Read the body FIRST, whatever the
        // status — that envelope carries the real reason (nft's "Interface
        // does not exist" plus the offending line). Only when the body isn't
        // an envelope that says something (5xx from a middleware,
        // ProblemDetails, plaintext) do we synthesize a Fail from the status,
        // which is still better than "Success=false, Message=null".
        var statusFallback = $"Daemon returned HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}";

        ServiceResponse<T>? envelope = null;
        try
        {
            envelope = await resp.Content.ReadFromJsonAsync<ServiceResponse<T>>(JsonOpts, ct);
        }
        catch
        {
            // Non-JSON / empty body — fall through to the status fallback.
        }

        if (resp.IsSuccessStatusCode)
        {
            return envelope ?? ServiceResponse<T>.Fail(statusFallback);
        }

        // Non-2xx: trust the body only when it actually explains itself.
        if (envelope is not null && !string.IsNullOrWhiteSpace(envelope.Message))
        {
            return envelope.Success
                ? ServiceResponse<T>.Fail(envelope.Message)   // status and body disagree — the status wins
                : envelope;
        }
        return ServiceResponse<T>.Fail(statusFallback);
    }

    private static string ResolveSocketPath(string raw) =>
        Path.IsPathRooted(raw) ? raw : Path.GetFullPath(raw, Directory.GetCurrentDirectory());

    public void Dispose()
    {
        if (_disposed) return;
        _http.Dispose();
        _disposed = true;
    }
}
