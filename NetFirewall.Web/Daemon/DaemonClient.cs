using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using NetFirewall.Models;
using NetFirewall.Models.System;
using NetFirewall.Web.Auth;

namespace NetFirewall.Web.Daemon;

public sealed class DaemonClient : IDaemonClient, IDisposable
{
    private static readonly JsonSerializerOptions JsonOpts = new(JsonSerializerDefaults.Web);

    private readonly HttpClient _http;
    private readonly DaemonClientOptions _opts;
    private readonly IHttpContextAccessor _httpContext;
    private readonly ILogger<DaemonClient> _logger;
    private bool _disposed;

    public DaemonClient(
        IOptions<DaemonClientOptions> opts,
        IHttpContextAccessor httpContext,
        ILogger<DaemonClient> logger)
    {
        _opts = opts.Value;
        _httpContext = httpContext;
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

    /// <summary>
    /// Send a POST, forward the session token from the inbound request's cookie,
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

    private void AttachSessionHeader(HttpRequestMessage req)
    {
        var ctx = _httpContext.HttpContext;
        if (ctx is null) return;
        if (ctx.Request.Cookies.TryGetValue(SessionCookieAuthHandler.CookieName, out var token) && !string.IsNullOrEmpty(token))
        {
            req.Headers.TryAddWithoutValidation(_opts.SessionHeader, token);
        }
    }

    private static async Task<ServiceResponse<T>> ReadEnvelopeAsync<T>(HttpResponseMessage resp, CancellationToken ct)
    {
        // Daemon always returns ServiceResponse<T> JSON (200 or 4xx/5xx).
        try
        {
            var envelope = await resp.Content.ReadFromJsonAsync<ServiceResponse<T>>(JsonOpts, ct);
            if (envelope is not null) return envelope;
        }
        catch
        {
            // Non-JSON body — fall through to generic failure.
        }
        var msg = $"Daemon returned HTTP {(int)resp.StatusCode} {resp.ReasonPhrase}";
        return ServiceResponse<T>.Fail(msg);
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
