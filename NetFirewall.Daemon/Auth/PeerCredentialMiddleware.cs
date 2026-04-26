using System.Net.Sockets;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.Extensions.Options;

namespace NetFirewall.Daemon.Auth;

/// <summary>
/// First defensive layer: rejects any connection whose Unix-socket peer UID
/// is not the configured <see cref="DaemonOptions.ExpectedPeerUid"/>.
/// File-system permissions on the socket already gate <em>who can connect</em>,
/// but checking peer UID inside the process means a misconfigured umask or a
/// debug-time bind to a wider mode does not silently expose us.
/// </summary>
public sealed class PeerCredentialMiddleware
{
    private readonly RequestDelegate _next;
    private readonly DaemonOptions _opts;
    private readonly ILogger<PeerCredentialMiddleware> _logger;

    public PeerCredentialMiddleware(
        RequestDelegate next,
        IOptions<DaemonOptions> opts,
        ILogger<PeerCredentialMiddleware> logger)
    {
        _next = next;
        _opts = opts.Value;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        if (_opts.ExpectedPeerUid is null)
        {
            // Dev mode — file-system perms (typically 0600 owned by current user)
            // are the only gate. Skip the in-process check and continue.
            await _next(context);
            return;
        }

        var actual = TryGetPeerUid(context);
        if (actual is null)
        {
            _logger.LogWarning("Could not read peer credentials; rejecting connection.");
            context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            await context.Response.WriteAsync("peer credentials unavailable");
            return;
        }

        if (actual.Value != _opts.ExpectedPeerUid.Value)
        {
            _logger.LogWarning(
                "Rejected connection from peer UID {Actual} (expected {Expected}).",
                actual.Value, _opts.ExpectedPeerUid.Value);
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsync("peer not authorized");
            return;
        }

        await _next(context);
    }

    /// <summary>
    /// Read the peer UID via SO_PEERCRED-style APIs. Linux exposes these via
    /// the IConnectionSocketFeature on the underlying socket; macOS exposes
    /// them similarly through SOL_LOCAL/LOCAL_PEERCRED. We use the simpler
    /// route exposed by Kestrel — Connections.Features — and fall back to
    /// raw socket options if needed.
    /// </summary>
    private static int? TryGetPeerUid(HttpContext context)
    {
        var socketFeature = context.Features.Get<IConnectionSocketFeature>();
        var socket = socketFeature?.Socket;
        if (socket is null || socket.AddressFamily != AddressFamily.Unix) return null;

        try
        {
            // Linux: SOL_SOCKET (1) + SO_PEERCRED (17) → ucred { pid, uid, gid }
            // macOS: SOL_LOCAL (0) + LOCAL_PEERCRED (1)  → xucred { version, uid, ngroups, groups[16] }
            if (OperatingSystem.IsLinux())
            {
                var buf = new byte[12]; // pid(4) + uid(4) + gid(4)
                socket.GetRawSocketOption(1, 17, buf);
                return BitConverter.ToInt32(buf, 4);
            }
            if (OperatingSystem.IsMacOS())
            {
                // xucred is up to 76 bytes; uid lives at offset 4.
                var buf = new byte[76];
                socket.GetRawSocketOption(0, 1, buf);
                return BitConverter.ToInt32(buf, 4);
            }
        }
        catch
        {
            // Either platform doesn't support it or the call failed; treat as missing.
        }
        return null;
    }
}
