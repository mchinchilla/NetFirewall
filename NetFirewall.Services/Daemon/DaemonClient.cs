using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.System;

namespace NetFirewall.Services.Daemon;

public sealed class DaemonClient : IDaemonClient, IDisposable
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _http;
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
        var handler = new SocketsHttpHandler
        {
            ConnectCallback = async (ctx, ct) =>
            {
                var s = new Socket(AddressFamily.Unix, SocketType.Stream, ProtocolType.Unspecified);
                await s.ConnectAsync(new UnixDomainSocketEndPoint(socketPath), ct);
                return new NetworkStream(s, ownsSocket: true);
            }
        };
        _http = new HttpClient(handler)
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

    public Task<ServiceResponse<TopTalkersDto>> GetTopTalkersAsync(int hours = 24, int limit = 5, CancellationToken ct = default)
        => GetAsync<TopTalkersDto>($"/v1/system/top-talkers?hours={hours}&limit={limit}", ct);

    public Task<ServiceResponse<WanHealthDto>> GetWanHealthAsync(CancellationToken ct = default)
        => GetAsync<WanHealthDto>("/v1/system/wan-health", ct);

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

    private static async Task<ServiceResponse<T>> ReadEnvelopeAsync<T>(HttpResponseMessage resp, CancellationToken ct)
    {
        // Daemon's contract: always 200 + ServiceResponse<T> JSON, even for
        // operation failures (Success=false in the envelope). Anything else
        // (5xx from a middleware, ProblemDetails JSON, plaintext) means the
        // daemon itself is broken — synthesize a Fail with the HTTP status so
        // the operator sees something more useful than "Success=false, Message=null".
        var statusFallback = $"Daemon returned HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}";
        if (!resp.IsSuccessStatusCode)
        {
            return ServiceResponse<T>.Fail(statusFallback);
        }

        try
        {
            var envelope = await resp.Content.ReadFromJsonAsync<ServiceResponse<T>>(JsonOpts, ct);
            if (envelope is not null) return envelope;
        }
        catch
        {
            // Non-JSON body — fall through to generic failure.
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
