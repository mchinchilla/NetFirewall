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

    public static void MapTerminalEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/v1/terminal")
            .RequireAuthorization(p => p.RequireRole(UserRoles.Admin));

        grp.MapPost("/open", OpenAsync);
        grp.MapGet("/attach", AttachAsync);
    }

    // ---- POST /v1/terminal/open -------------------------------------------------
    // Services are resolved from IServiceProvider INSIDE the try/catch rather than
    // as handler parameters: resolving IUserTotpService pulls in ITotpSecretCipher,
    // whose AesGcmTotpSecretCipher ctor throws if NETFIREWALL_MASTER_KEY is missing.
    // As a handler parameter that activation failure escapes as a bare 500 (before
    // the handler body); resolved here it becomes a clean ServiceResponse with a
    // pointed message ("daemon is missing the master key").
    private static async Task<IResult> OpenAsync(
        TerminalOpenRequest req,
        HttpContext ctx,
        IServiceProvider sp,
        ILoggerFactory loggerFactory,
        CancellationToken ct)
    {
        var log = loggerFactory.CreateLogger("TerminalOpen");
        try
        {
            var (userId, sessionId, username) = Identity(ctx);
            if (userId is null || sessionId is null)
                return Results.Json(ServiceResponse<TerminalTicketResponse>.Fail("Not authenticated."), statusCode: 200);

            if (string.IsNullOrWhiteSpace(req?.Code))
                return Results.Json(ServiceResponse<TerminalTicketResponse>.Fail("A TOTP code is required to open the terminal."), statusCode: 200);

            IUserTotpService totp;
            try
            {
                totp = sp.GetRequiredService<IUserTotpService>();
            }
            catch (Exception ex)
            {
                // Almost always: the daemon process is missing NETFIREWALL_MASTER_KEY
                // (set it in the daemon's EnvironmentFile and restart). Surface a
                // pointed message instead of an opaque 500.
                log.LogError(ex, "Terminal open: TOTP service could not be activated (master key missing?)");
                return Results.Json(ServiceResponse<TerminalTicketResponse>.Fail(
                    "The daemon cannot verify TOTP — it is missing NETFIREWALL_MASTER_KEY. " +
                    "Set the same master key as the Web in the daemon's environment and restart it."),
                    statusCode: 200);
            }

            var registry = sp.GetRequiredService<ITerminalSessionRegistry>();
            var audit = sp.GetRequiredService<IAuthAuditService>();

            // Fresh TOTP — the daemon owns the cipher key, so it verifies directly.
            var ok = await totp.VerifyAsync(userId.Value, req.Code, ct);
            if (!ok)
            {
                await audit.LogAsync(AuthAuditEvents.TerminalDenied, userId, username, ClientIp(ctx),
                    detail: new { reason = "totp_failed" }, ct: ct);
                return Results.Json(ServiceResponse<TerminalTicketResponse>.Fail("Invalid TOTP code."), statusCode: 200);
            }

            var ticket = registry.IssueTicket(userId.Value, sessionId.Value);
            await audit.LogAsync(AuthAuditEvents.TerminalOpened, userId, username, ClientIp(ctx), ct: ct);
            return Results.Json(ServiceResponse<TerminalTicketResponse>.Ok(
                new TerminalTicketResponse(ticket), "Terminal authorized."));
        }
        catch (Exception ex)
        {
            // Never leak a bare 500 — the daemon contract is always a ServiceResponse
            // envelope so the Web shows a real message. The detail goes to the log only.
            log.LogError(ex, "Terminal open failed");
            return Results.Json(
                ServiceResponse<TerminalTicketResponse>.Fail("Could not open the terminal — see daemon log."),
                statusCode: 200);
        }
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
        // watchdog is reset on every byte either direction. lastActivity is a long
        // (UTC ticks) touched by three tasks, so reads/writes go through Volatile/
        // Interlocked — a DateTimeOffset would tear.
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted);
        lifetime.CancelAfter(MaxLifetime);
        long lastActivityTicks = DateTime.UtcNow.Ticks;
        void Touch() => Volatile.Write(ref lastActivityTicks, DateTime.UtcNow.Ticks);

        Task ptyToWs = Task.CompletedTask, wsToPty = Task.CompletedTask, idleWatch = Task.CompletedTask;
        try
        {
            // Interactive shell with a real environment. NOT a login shell (-l):
            // login shells read /etc/profile + profile.d which, under the daemon's
            // sandbox, can error out and exit instantly (blank terminal). A normal
            // interactive shell on a PTY is the robust choice. HOME/USER/etc. must
            // be set or bash exits immediately when it can't resolve the user env.
            var (shell, args) = ResolveShell();
            var env = new Dictionary<string, string>
            {
                ["TERM"] = "xterm-256color",
                ["HOME"] = "/root",
                ["USER"] = "root",
                ["LOGNAME"] = "root",
                ["SHELL"] = shell,
                ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                ["PS1"] = @"\u@\h:\w\$ ",
            };
            session = pty.Start(shell, args, PtySize.Default, env);
            var pump = session; // non-null capture for the closures

            // PTY → WS pump (shell output to browser).
            ptyToWs = Task.Run(async () =>
            {
                var buf = new byte[8192];
                try
                {
                    while (!lifetime.IsCancellationRequested)
                    {
                        int n;
                        try { n = await pump.ReadAsync(buf, lifetime.Token); }
                        catch (IOException) { break; }            // EIO on master = shell exited
                        catch (OperationCanceledException) { break; }
                        if (n <= 0) break;                        // EOF = shell exited
                        Touch();
                        await ws.SendAsync(buf.AsMemory(0, n), WebSocketMessageType.Binary, true, lifetime.Token);
                    }
                }
                catch (Exception ex) when (ex is OperationCanceledException or WebSocketException or ObjectDisposedException) { }
            }, lifetime.Token);

            // WS → PTY pump (browser keystrokes + control frames to shell).
            wsToPty = Task.Run(async () =>
            {
                var buf = new byte[8192];
                try
                {
                    while (!lifetime.IsCancellationRequested)
                    {
                        var result = await ws.ReceiveAsync(buf, lifetime.Token);
                        if (result.MessageType == WebSocketMessageType.Close) { closeReason = "user"; break; }
                        Touch();

                        if (result.MessageType == WebSocketMessageType.Text)
                        {
                            // Control channel: JSON like {"t":"resize","rows":40,"cols":120}.
                            if (TryHandleControl(buf.AsSpan(0, result.Count), pump)) continue;
                        }
                        // Otherwise raw keystrokes → shell stdin.
                        await pump.WriteAsync(buf.AsMemory(0, result.Count), lifetime.Token);
                    }
                }
                catch (Exception ex) when (ex is OperationCanceledException or WebSocketException or ObjectDisposedException) { }
            }, lifetime.Token);

            // Idle watchdog: cancel the whole thing if no traffic for IdleTimeout.
            idleWatch = Task.Run(async () =>
            {
                try
                {
                    while (!lifetime.IsCancellationRequested)
                    {
                        await Task.Delay(TimeSpan.FromSeconds(15), lifetime.Token);
                        var idle = DateTime.UtcNow.Ticks - Volatile.Read(ref lastActivityTicks);
                        if (idle > IdleTimeout.Ticks)
                        {
                            closeReason = "idle";
                            lifetime.Cancel();
                            break;
                        }
                    }
                }
                catch (OperationCanceledException) { }
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
            // Await the pumps BEFORE disposing the PTY / closing the WS — otherwise
            // DisposeAsync closes the master fd while a pump is mid read/write
            // (ObjectDisposedException), and a concurrent ws.Send vs ws.Close throws.
            lifetime.Cancel();
            await Task.WhenAll(Swallow(ptyToWs), Swallow(wsToPty), Swallow(idleWatch));
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

    /// <summary>Await a task and swallow any fault — used on teardown where the
    /// pumps fault with cancellation/disposed/WS errors that are expected.</summary>
    private static async Task Swallow(Task t) { try { await t; } catch { /* expected on teardown */ } }

    /// <summary>Parse a JSON control frame; returns true if it was a control message.
    /// Tolerant of malformed input from a buggy/hostile client — never throws (the
    /// caller is on a root shell, so a bad frame must not crash the pump).</summary>
    private static bool TryHandleControl(ReadOnlySpan<byte> bytes, IPtySession session)
    {
        // Cheap guard: control frames start with '{'.
        if (bytes.Length == 0 || bytes[0] != (byte)'{') return false;
        try
        {
            using var doc = JsonDocument.Parse(bytes.ToArray());
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return false;
            if (!root.TryGetProperty("t", out var t) || t.ValueKind != JsonValueKind.String) return false;
            if (t.GetString() == "resize" &&
                root.TryGetProperty("rows", out var r) && r.TryGetInt32(out var rows) &&
                root.TryGetProperty("cols", out var c) && c.TryGetInt32(out var cols))
            {
                session.Resize(new PtySize((ushort)Math.Clamp(rows, 1, 1000),
                                           (ushort)Math.Clamp(cols, 1, 1000)));
                return true;
            }
        }
        catch (Exception) { /* malformed → treat as keystrokes, never crash the pump */ }
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

    /// <summary>Pick an interactive shell, preferring bash, falling back to sh
    /// (Alpine/busybox ISO target ships /bin/sh, not /bin/bash). The "-i" forces
    /// interactive mode so the prompt + line editing work even though stdin is a
    /// PTY (bash usually infers this, but being explicit is harmless and helps sh).</summary>
    private static (string shell, string[] args) ResolveShell()
    {
        if (File.Exists("/bin/bash")) return ("/bin/bash", new[] { "-i" });
        if (File.Exists("/usr/bin/bash")) return ("/usr/bin/bash", new[] { "-i" });
        return ("/bin/sh", new[] { "-i" });
    }

    public sealed record TerminalOpenRequest(string? Code);
    public sealed record TerminalTicketResponse(string Ticket);
}
