using System.Net.WebSockets;
using NetFirewall.Services.Daemon;

namespace NetFirewall.Web.Services;

/// <summary>
/// Pumps bytes both ways between the browser WebSocket (terminated at the Web) and
/// the daemon WebSocket (the root PTY). Keeps the controller thin (rule #10): the
/// controller just authenticates, accepts the browser socket, and hands off here.
/// The Web is a dumb relay — it never inspects or rewrites the stream, so the
/// browser's cookie never reaches the daemon and the daemon session token never
/// reaches the browser.
/// </summary>
public interface ITerminalProxyService
{
    /// <summary>
    /// Open the daemon PTY socket for <paramref name="ticket"/> and relay frames to/from
    /// <paramref name="browser"/> until either side closes. Tears both down on exit.
    /// </summary>
    Task PumpAsync(WebSocket browser, string ticket, CancellationToken ct);
}

public sealed class TerminalProxyService : ITerminalProxyService
{
    private readonly IDaemonClient _daemon;
    private readonly ILogger<TerminalProxyService> _logger;

    public TerminalProxyService(IDaemonClient daemon, ILogger<TerminalProxyService> logger)
    {
        _daemon = daemon;
        _logger = logger;
    }

    public async Task PumpAsync(WebSocket browser, string ticket, CancellationToken ct)
    {
        WebSocket daemon;
        try
        {
            daemon = await _daemon.ConnectTerminalAsync(ticket, ct);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to open daemon terminal socket");
            await TryCloseAsync(browser, WebSocketCloseStatus.InternalServerError, "daemon unreachable");
            return;
        }

        using (daemon)
        {
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var b2d = RelayAsync(browser, daemon, linked.Token);
            var d2b = RelayAsync(daemon, browser, linked.Token);
            await Task.WhenAny(b2d, d2b);
            linked.Cancel(); // unblock the other direction
            await Task.WhenAll(SwallowAsync(b2d), SwallowAsync(d2b));
            await TryCloseAsync(daemon, WebSocketCloseStatus.NormalClosure, "closed");
            await TryCloseAsync(browser, WebSocketCloseStatus.NormalClosure, "closed");
        }
    }

    private static async Task RelayAsync(WebSocket from, WebSocket to, CancellationToken ct)
    {
        var buf = new byte[8192];
        while (!ct.IsCancellationRequested && from.State == WebSocketState.Open)
        {
            WebSocketReceiveResult r;
            try { r = await from.ReceiveAsync(buf, ct); }
            catch (OperationCanceledException) { break; }
            catch (WebSocketException) { break; }

            if (r.MessageType == WebSocketMessageType.Close) break;
            if (to.State != WebSocketState.Open) break;

            // Preserve message type + end-of-message framing so xterm's binary
            // frames and the JSON control frames pass through unchanged.
            await to.SendAsync(buf.AsMemory(0, r.Count), r.MessageType, r.EndOfMessage, ct);
        }
    }

    private static async Task SwallowAsync(Task t)
    {
        try { await t; } catch { /* relay already logged / benign on teardown */ }
    }

    private static async Task TryCloseAsync(WebSocket ws, WebSocketCloseStatus status, string reason)
    {
        try
        {
            if (ws.State == WebSocketState.Open || ws.State == WebSocketState.CloseReceived)
                await ws.CloseAsync(status, reason, CancellationToken.None);
        }
        catch { /* best effort */ }
    }
}
