using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NetFirewall.Models;
using NetFirewall.Models.System;
using NetFirewall.Web.Auth;
using NetFirewall.Services.Daemon;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// Real Unix-socket coverage for <see cref="DaemonClient"/>. We boot a tiny
/// Kestrel server bound to a UDS path and have the client speak HTTP to it.
/// This proves the wire format and the failure surface, not just a mocked
/// HttpClient round-trip — and crucially pins the session-header forwarding
/// (<c>X-NetFw-Session</c>) the daemon uses to authenticate the proxied call.
/// </summary>
public sealed class DaemonClientTests : IAsyncLifetime
{
    private string _socketPath = "";
    private WebApplication? _server;
    private readonly List<RecordedRequest> _received = new();

    private sealed record RecordedRequest(string Path, string? SessionHeader, string Body);

    public async Task InitializeAsync()
    {
        // Each test gets its own socket path. Using Path.GetTempFileName + delete
        // gives us a guaranteed-unique short path that fits in sun_path (~108 chars).
        _socketPath = Path.GetTempFileName();
        File.Delete(_socketPath);

        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(o => o.ListenUnixSocket(_socketPath));

        var app = builder.Build();
        // Capture every request so tests can assert on them.
        app.MapPost("/v1/crypto/encrypt", async (HttpContext ctx) =>
        {
            var body = await new StreamReader(ctx.Request.Body).ReadToEndAsync();
            _received.Add(new RecordedRequest(ctx.Request.Path, ctx.Request.Headers["X-NetFw-Session"].ToString(), body));
            return Results.Ok(new { success = true, message = (string?)null,
                data = new { data = Convert.ToBase64String(new byte[] { 9, 9, 9 }) } });
        });
        app.MapPost("/v1/crypto/decrypt", async (HttpContext ctx) =>
        {
            var body = await new StreamReader(ctx.Request.Body).ReadToEndAsync();
            _received.Add(new RecordedRequest(ctx.Request.Path, ctx.Request.Headers["X-NetFw-Session"].ToString(), body));
            return Results.Ok(new { success = true, data = new { data = Convert.ToBase64String(new byte[] { 1, 2, 3 }) } });
        });
        app.MapPost("/v1/network/{id}/apply", (string id, HttpContext ctx) =>
        {
            _received.Add(new RecordedRequest($"/v1/network/{id}/apply", ctx.Request.Headers["X-NetFw-Session"].ToString(), ""));
            return Results.Ok(new { success = true, message = "applied",
                data = new { success = true, message = "applied", exitCode = 0 } });
        });
        app.MapPost("/v1/firewall/apply", (HttpContext ctx) =>
        {
            _received.Add(new RecordedRequest("/v1/firewall/apply", ctx.Request.Headers["X-NetFw-Session"].ToString(), ""));
            return Results.Ok(new { success = true, message = "applied",
                data = new { exitCode = 0, backupPath = "/var/lib/x.conf", output = "ok", error = (string?)null } });
        });
        app.MapGet("/v1/firewall/current-ruleset", (HttpContext ctx) =>
        {
            _received.Add(new RecordedRequest("/v1/firewall/current-ruleset", ctx.Request.Headers["X-NetFw-Session"].ToString(), ""));
            return Results.Text("table inet filter {}", "text/plain");
        });
        app.MapGet("/health", () => Results.Ok());

        // Endpoint that always 500s for failure-mapping tests.
        app.MapPost("/v1/firewall/apply-qos", () => Results.Problem("kaboom", statusCode: 500));

        _server = app;
        await _server.StartAsync();
    }

    public async Task DisposeAsync()
    {
        if (_server is not null) await _server.StopAsync();
        try { File.Delete(_socketPath); } catch { /* best effort */ }
    }

    private DaemonClient CreateClient(HttpContext? incoming = null)
    {
        var opts = Options.Create(new DaemonClientOptions
        {
            SocketPath = _socketPath,
            SessionHeader = "X-NetFw-Session",
            Timeout = TimeSpan.FromSeconds(5)
        });
        // The provider is exactly what the Web's WebDaemonSessionTokenProvider
        // does: read the cookie out of the (optional) inbound request.
        var tokenProvider = new StubSessionTokenProvider(incoming);
        return new DaemonClient(opts, tokenProvider, NullLogger<DaemonClient>.Instance);
    }

    private sealed class StubSessionTokenProvider : IDaemonSessionTokenProvider
    {
        private readonly HttpContext? _ctx;
        public StubSessionTokenProvider(HttpContext? ctx) { _ctx = ctx; }
        public string? GetCurrentToken()
        {
            if (_ctx is null) return null;
            return _ctx.Request.Cookies.TryGetValue(SessionCookieAuthHandler.CookieName, out var t) ? t : null;
        }
    }

    private static HttpContext IncomingWithSessionCookie(string token)
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Headers.Cookie = $"{SessionCookieAuthHandler.CookieName}={token}";
        return ctx;
    }

    // ── Crypto round-trip + session header forwarding ──────────────────

    [Fact]
    public async Task EncryptTotpAsync_RoundTripsBase64_AndForwardsSessionToken()
    {
        var ctx = IncomingWithSessionCookie("INBOUND-COOKIE-VALUE");
        using var client = CreateClient(ctx);

        var result = await client.EncryptTotpAsync(new byte[] { 1, 2, 3, 4, 5 });

        Assert.Equal(new byte[] { 9, 9, 9 }, result);
        var req = Assert.Single(_received);
        Assert.Equal("/v1/crypto/encrypt", req.Path);
        Assert.Equal("INBOUND-COOKIE-VALUE", req.SessionHeader);
        // Body should be JSON wrapping the base64-encoded plaintext.
        Assert.Contains(Convert.ToBase64String(new byte[] { 1, 2, 3, 4, 5 }), req.Body);
    }

    [Fact]
    public async Task EncryptTotpAsync_NoIncomingCookie_OmitsSessionHeader()
    {
        // Background calls (e.g. from a hosted service) may not have an HttpContext.
        // The client must still work — daemon-side auth is the daemon's problem.
        using var client = CreateClient(incoming: null);

        await client.EncryptTotpAsync(new byte[] { 1 });

        var req = Assert.Single(_received);
        Assert.Equal("", req.SessionHeader);
    }

    [Fact]
    public async Task DecryptTotpAsync_HappyPath_ReturnsBytes()
    {
        using var client = CreateClient();
        var result = await client.DecryptTotpAsync(new byte[] { 9, 9, 9 });
        Assert.Equal(new byte[] { 1, 2, 3 }, result);
    }

    // ── ServiceResponse envelope mapping ───────────────────────────────

    [Fact]
    public async Task ApplyInterfaceAsync_DaemonReturns2xxWithEnvelope_ParsesEnvelope()
    {
        var id = Guid.NewGuid();
        using var client = CreateClient();

        var envelope = await client.ApplyInterfaceAsync(id);

        Assert.True(envelope.Success);
        Assert.Equal("applied", envelope.Message);
        Assert.NotNull(envelope.Data);
        Assert.Equal(0, envelope.Data!.ExitCode);
        Assert.Single(_received, r => r.Path == $"/v1/network/{id}/apply");
    }

    [Fact]
    public async Task ApplyFirewallAsync_HappyPath_ParsesNftDtoFields()
    {
        using var client = CreateClient();
        var envelope = await client.ApplyFirewallAsync();
        Assert.True(envelope.Success);
        Assert.NotNull(envelope.Data);
        Assert.Equal("/var/lib/x.conf", envelope.Data!.BackupPath);
        Assert.Equal("ok", envelope.Data.Output);
    }

    [Fact]
    public async Task ApplyQosAsync_DaemonReturns500_ReturnsFailEnvelope_NoThrow()
    {
        // The daemon endpoint above throws ProblemDetails (500). The client
        // must turn that into a ServiceResponse.Fail("Daemon returned HTTP 500..."),
        // not propagate as an unhandled exception.
        using var client = CreateClient();

        var envelope = await client.ApplyQosAsync();

        Assert.False(envelope.Success);
        Assert.Contains("500", envelope.Message);
    }

    // ── GetCurrentRulesetAsync ─────────────────────────────────────────

    [Fact]
    public async Task GetCurrentRulesetAsync_ReturnsRawTextBody()
    {
        using var client = CreateClient();
        var ruleset = await client.GetCurrentRulesetAsync();
        Assert.Equal("table inet filter {}", ruleset);
    }

    // ── Liveness probe ────────────────────────────────────────────────

    [Fact]
    public async Task IsAliveAsync_DaemonResponding_ReturnsTrue()
    {
        using var client = CreateClient();
        Assert.True(await client.IsAliveAsync());
    }

    [Fact]
    public async Task IsAliveAsync_SocketGone_ReturnsFalse_NoThrow()
    {
        // Stop the server so the next probe fails to connect. The client must
        // NOT propagate the SocketException — a misconfigured Web with a dead
        // daemon should still load the page and surface a "daemon offline" UI.
        await _server!.StopAsync();
        try { File.Delete(_socketPath); } catch { /* best effort */ }
        using var client = CreateClient();

        Assert.False(await client.IsAliveAsync());
    }

    // ── Connection error mapping (network-side failures) ──────────────

    [Fact]
    public async Task PostFailsToConnect_ReturnsFailEnvelope_NoThrow()
    {
        await _server!.StopAsync();
        try { File.Delete(_socketPath); } catch { /* best effort */ }
        using var client = CreateClient();

        var envelope = await client.ApplyFirewallAsync();

        Assert.False(envelope.Success);
        Assert.Contains("Daemon unreachable", envelope.Message);
    }
}
