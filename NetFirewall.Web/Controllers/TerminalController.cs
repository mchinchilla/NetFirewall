using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Daemon;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Services;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// Web-terminal entry points. Admin-only. Opening requires a fresh TOTP (verified
/// by the daemon, which owns the cipher key); the daemon returns a one-time attach
/// ticket that the browser then presents on the WebSocket. The controller is a thin
/// orchestrator (rule #10) — TOTP/PTY logic lives in the daemon, the byte pump in
/// <see cref="ITerminalProxyService"/>.
/// </summary>
[Authorize(Roles = UserRoles.Admin)]
public sealed class TerminalController : Controller
{
    private readonly IDaemonClient _daemon;
    private readonly ITerminalProxyService _proxy;
    private readonly ILogger<TerminalController> _logger;

    public TerminalController(
        IDaemonClient daemon,
        ITerminalProxyService proxy,
        ILogger<TerminalController> logger)
    {
        _daemon = daemon;
        _proxy = proxy;
        _logger = logger;
    }

    [HttpGet("/terminal")]
    public IActionResult Index() => View();

    // Fresh-TOTP gate. Returns a one-time attach ticket the browser hands to the WS.
    [HttpPost("/terminal/open"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Open([FromForm] string code, CancellationToken ct)
    {
        var result = await _daemon.OpenTerminalAsync(code ?? string.Empty, ct);
        return this.ToHtmxResponse(result);
    }

    // WebSocket proxy. The browser connects here (same-origin, cookie-authed); we
    // open the daemon PTY socket with the ticket and relay bytes.
    [HttpGet("/terminal/ws")]
    public async Task Ws([FromQuery] string ticket, CancellationToken ct)
    {
        if (!HttpContext.WebSockets.IsWebSocketRequest)
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        // CSRF defense for the WS upgrade: WebSockets aren't covered by antiforgery
        // tokens and SameSite alone is insufficient, so reject cross-origin upgrades.
        // The unguessable one-time ticket (read from a same-origin fetch body) is the
        // primary defense; this is belt-and-suspenders.
        if (!IsSameOrigin())
        {
            Response.StatusCode = StatusCodes.Status403Forbidden;
            _logger.LogWarning("Rejected cross-origin terminal WS upgrade from origin '{Origin}'",
                Request.Headers.Origin.ToString());
            return;
        }

        if (string.IsNullOrEmpty(ticket))
        {
            Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        using var browser = await HttpContext.WebSockets.AcceptWebSocketAsync();
        await _proxy.PumpAsync(browser, ticket, ct);
    }

    private bool IsSameOrigin()
    {
        var origin = Request.Headers.Origin.ToString();
        if (string.IsNullOrEmpty(origin)) return true; // non-browser / same-origin nav without Origin
        return Uri.TryCreate(origin, UriKind.Absolute, out var o)
            && string.Equals(o.Host, Request.Host.Host, StringComparison.OrdinalIgnoreCase)
            && (!Request.Host.Port.HasValue || o.Port == Request.Host.Port.Value);
    }
}
