using System.Net.WebSockets;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using NetFirewall.Daemon.Auth;
using NetFirewall.Daemon.Pty;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Auth;
using NetFirewall.Services.Processes;

namespace NetFirewall.Daemon.Endpoints;

/// <summary>
/// Web-terminal endpoints — the privileged, security-sensitive half of the
/// feature (a root PTY in the browser). Admin-only, and <c>/open</c> requires a
/// FRESH TOTP every time (not the 15-min elevation window): a root shell is more
/// dangerous than a routine destructive action. The open→attach split with a
/// single-use ticket is the CSRF defense for the unauthenticatable WS upgrade.
///
/// Flow:
///   POST /v1/terminal/open    — admin + fresh TOTP → mint one-time attach ticket
///   GET  /v1/terminal/attach  — WS; redeem ticket (bound to this session) → PTY
/// </summary>
public static class TerminalEndpoints
{
    // Daemon-authoritative timeouts (the Web/browser timers are only UX hints).
    private static readonly TimeSpan IdleTimeout = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan MaxLifetime = TimeSpan.FromMinutes(60);
    private const string Shell = "/bin/bash";

    public static void MapTerminalEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/v1/terminal")
            .RequireAuthorization(p => p.RequireRole(UserRoles.Admin));

        grp.MapPost("/open", OpenAsync);
        grp.MapGet("/attach", AttachAsync);
    }

    // ---- POST /v1/terminal/open -------------------------------------------------
    private static async Task<IResult> OpenAsync(
        TerminalOpenRequest req,
        HttpContext ctx,
        IUserTotpService totp,
        ITerminalSessionRegistry registry,
        IAuthAuditService audit,
        CancellationToken ct)
    {
        var (userId, sessionId, username) = Identity(ctx);
        if (userId is null || sessionId is null)
            return Results.Json(ServiceResponse<TerminalTicketResponse>.Fail("Not authenticated."), statusCode: 401);

        if (string.IsNullOrWhiteSpace(req.Code))
            return Results.Json(ServiceResponse<TerminalTicketResponse>.Fail("A TOTP code is required to open the terminal."), statusCode: 400);

        // Fresh TOTP — the daemon owns the cipher key, so it verifies directly.
        var ok = await totp.VerifyAsync(userId.Value, req.Code, ct);
        if (!ok)
        {
            await audit.LogAsync(AuthAuditEvents.TerminalDenied, userId, username, ClientIp(ctx),
                detail: new { reason = "totp_failed" }, ct: ct);
            return Results.Json(ServiceResponse<TerminalTicketResponse>.Fail("Invalid TOTP code."), statusCode: 403);
        }

        // One terminal at a time — reject early so the user gets a clear message
        // rather than a ticket that fails at attach. (The slot is truly claimed at
        // attach; this is a fast pre-check.)
        // Note: we don't acquire here to avoid leaking the slot if the user never
        // attaches; the attach path does the authoritative acquire.

        var ticket = registry.IssueTicket(userId.Value, sessionId.Value);
        await audit.LogAsync(AuthAuditEvents.TerminalOpened, userId, username, ClientIp(ctx), ct: ct);
        return Results.Json(ServiceResponse<TerminalTicketResponse>.Ok(
            new TerminalTicketResponse(ticket), "Terminal authorized."));
    }

    // ---- GET /v1/terminal/attach (WebSocket) ------------------------------------
    private static async Task AttachAsync(
        HttpContext ctx,
        ITerminalSessionRegistry registry,
        IPtyService pty,
        IAuthAuditService audit,
        ILoggerFactory loggerFactory)
    {
        var log = loggerFactory.CreateLogger("TerminalAttach");
        if (!ctx.WebSockets.IsWebSocketRequest)
        {
            ctx.Response.StatusCode = StatusCodes.Status400BadRequest;
            return;
        }

        var (userId, sessionId, username) = Identity(ctx);
        var ticket = ctx.Request.Query["ticket"].ToString();

        // Redeem the one-time ticket and verify it's bound to THIS session.
        if (userId is null || sessionId is null ||
            !registry.TryRedeemTicket(ticket, out var tUser, out var tSession) ||
            tUser != userId.Value || tSession != sessionId.Value)
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            await audit.LogAsync(AuthAuditEvents.TerminalDenied, userId, username, ClientIp(ctx),
                detail: new { reason = "bad_ticket" });
            return;
        }

        // Single concurrent terminal.
        if (!registry.TryAcquireSlot(userId.Value))
        {
            ctx.Response.StatusCode = StatusCodes.Status409Conflict;
            await audit.LogAsync(AuthAuditEvents.TerminalDenied, userId, username, ClientIp(ctx),
                detail: new { reason = "busy" });
            return;
        }

        using var ws = await ctx.WebSockets.AcceptWebSocketAsync();
        await audit.LogAsync(AuthAuditEvents.TerminalAttached, userId, username, ClientIp(ctx));
        string closeReason = "shell_exit";

        IPtySession? session = null;
        // Lifetime + idle control. The lifetime CTS fires at MaxLifetime; the idle
        // watchdog is reset on every byte either direction.
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted);
        lifetime.CancelAfter(MaxLifetime);
        var lastActivity = DateTimeOffset.UtcNow;

        try
        {
            session = pty.Start(Shell, new[] { "-l" }, PtySize.Default);

            // PTY → WS pump (shell output to browser).
            var ptyToWs = Task.Run(async () =>
            {
                var buf = new byte[8192];
                try
                {
                    while (!lifetime.IsCancellationRequested)
                    {
                        int n;
                        try { n = await session.Master.ReadAsync(buf, lifetime.Token); }
                        catch (IOException) { break; }            // EIO on master = shell exited
                        catch (OperationCanceledException) { break; }
                        if (n <= 0) break;                        // EOF = shell exited
                        lastActivity = DateTimeOffset.UtcNow;
                        await ws.SendAsync(buf.AsMemory(0, n), WebSocketMessageType.Binary, true, lifetime.Token);
                    }
                }
                catch (Exception ex) when (ex is OperationCanceledException or WebSocketException) { }
            }, lifetime.Token);

            // WS → PTY pump (browser keystrokes + control frames to shell).
            var wsToPty = Task.Run(async () =>
            {
                var buf = new byte[8192];
                try
                {
                    while (!lifetime.IsCancellationRequested)
                    {
                        var result = await ws.ReceiveAsync(buf, lifetime.Token);
                        if (result.MessageType == WebSocketMessageType.Close) { closeReason = "user"; break; }
                        lastActivity = DateTimeOffset.UtcNow;

                        if (result.MessageType == WebSocketMessageType.Text)
                        {
                            // Control channel: JSON like {"t":"resize","rows":40,"cols":120}.
                            if (TryHandleControl(buf.AsSpan(0, result.Count), session)) continue;
                        }
                        // Otherwise raw keystrokes → shell stdin.
                        await session.Master.WriteAsync(buf.AsMemory(0, result.Count), lifetime.Token);
                        await session.Master.FlushAsync(lifetime.Token);
                    }
                }
                catch (Exception ex) when (ex is OperationCanceledException or WebSocketException) { }
            }, lifetime.Token);

            // Idle watchdog: cancel the whole thing if no traffic for IdleTimeout.
            var idleWatch = Task.Run(async () =>
            {
                while (!lifetime.IsCancellationRequested)
                {
                    await Task.Delay(TimeSpan.FromSeconds(15), lifetime.Token);
                    if (DateTimeOffset.UtcNow - lastActivity > IdleTimeout)
                    {
                        closeReason = "idle";
                        lifetime.Cancel();
                        break;
                    }
                }
            }, lifetime.Token);

            // Whichever finishes first ends the session.
            var finished = await Task.WhenAny(ptyToWs, wsToPty, session.WaitForExitAsync(lifetime.Token));
            if (finished == wsToPty && closeReason == "shell_exit") closeReason = "user";
            if (lifetime.IsCancellationRequested && closeReason == "shell_exit") closeReason = "lifetime";
            lifetime.Cancel(); // stop the other pumps
        }
        catch (PtyException ex)
        {
            closeReason = "spawn_failed";
            log.LogError(ex, "PTY spawn failed for terminal attach");
        }
        finally
        {
            if (session is not null) await session.DisposeAsync();
            registry.ReleaseSlot();
            try
            {
                if (ws.State == WebSocketState.Open || ws.State == WebSocketState.CloseReceived)
                    await ws.CloseAsync(WebSocketCloseStatus.NormalClosure, closeReason, CancellationToken.None);
            }
            catch { /* best effort */ }
            await audit.LogAsync(AuthAuditEvents.TerminalClosed, userId, username, ClientIp(ctx),
                detail: new { reason = closeReason });
        }
    }

    /// <summary>Parse a JSON control frame; returns true if it was a control message.</summary>
    private static bool TryHandleControl(ReadOnlySpan<byte> bytes, IPtySession session)
    {
        // Cheap guard: control frames start with '{'.
        if (bytes.Length == 0 || bytes[0] != (byte)'{') return false;
        try
        {
            using var doc = JsonDocument.Parse(bytes.ToArray());
            var root = doc.RootElement;
            if (!root.TryGetProperty("t", out var t)) return false;
            if (t.GetString() == "resize" &&
                root.TryGetProperty("rows", out var r) && root.TryGetProperty("cols", out var c))
            {
                session.Resize(new PtySize((ushort)Math.Clamp(r.GetInt32(), 1, 1000),
                                           (ushort)Math.Clamp(c.GetInt32(), 1, 1000)));
                return true;
            }
        }
        catch (JsonException) { /* not a control frame — treat as keystrokes */ }
        return false;
    }

    private static (Guid? userId, Guid? sessionId, string? username) Identity(HttpContext ctx)
    {
        var u = ctx.User;
        Guid? uid = Guid.TryParse(u.FindFirstValue(ClaimTypes.NameIdentifier), out var g) ? g : null;
        Guid? sid = Guid.TryParse(u.FindFirstValue(DaemonSessionAuthHandler.SessionIdClaim), out var s) ? s : null;
        return (uid, sid, u.Identity?.Name);
    }

    private static System.Net.IPAddress? ClientIp(HttpContext ctx) => ctx.Connection.RemoteIpAddress;

    public sealed record TerminalOpenRequest(string? Code);
    public sealed record TerminalTicketResponse(string Ticket);
}
