using System.Net.Sockets;
using System.Security.Claims;
using Microsoft.AspNetCore.Connections.Features;
using NetFirewall.Models.Auth;

namespace NetFirewall.Daemon.Auth;

/// <summary>
/// Pipeline middleware (NOT an MVC filter) that grants a fully-elevated
/// system principal when the Unix-socket peer UID is 0 AND no session
/// header was attached. Runs after <c>UseAuthentication</c> and before
/// <c>UseAuthorization</c>, so any later authorization check sees
/// <c>HttpContext.User</c> as authenticated.
///
/// <para>Why a middleware and not an MVC filter: <c>RequireAuthorization()</c>
/// installs its filter at the endpoint level via the framework's authorization
/// middleware (<c>UseAuthorization</c>), which runs BEFORE MVC filters fire.
/// By the time an <c>IAuthorizationFilter</c> attribute would execute, the
/// request has already been rejected with 401 because <c>User</c> is anonymous.
/// A pipeline middleware can mutate <c>HttpContext.User</c> in time.</para>
///
/// <para>Defensible because: the daemon socket is mode 0660 root:netfirewall,
/// so the only way to be uid 0 here is to already be root on the box. The
/// Web (uid 999, netfirewall-web) still goes through the full session +
/// elevation flow.</para>
/// </summary>
public sealed class RootPeerBypassMiddleware
{
    private readonly RequestDelegate _next;

    public RootPeerBypassMiddleware(RequestDelegate next) => _next = next;

    public async Task InvokeAsync(HttpContext context)
    {
        // Only bypass when the caller didn't try to authenticate themselves.
        // If a session header is present we let the normal flow handle it —
        // that way a stale/wrong token doesn't get silently upgraded.
        var hasSessionHeader = context.Request.Headers.ContainsKey("X-NetFw-Session");
        if (!hasSessionHeader && context.User.Identity?.IsAuthenticated != true)
        {
            var uid = TryGetPeerUid(context);
            if (uid == 0)
            {
                var identity = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.Name, "system-bootstrap"),
                    new Claim(ClaimTypes.Role, "Admin"),
                    new Claim(DaemonSessionAuthHandler.AuthLevelClaim, AuthLevels.Elevated),
                }, authenticationType: "RootPeer");
                context.User = new ClaimsPrincipal(identity);
            }
        }

        await _next(context);
    }

    private static int? TryGetPeerUid(HttpContext context)
    {
        var socketFeature = context.Features.Get<IConnectionSocketFeature>();
        var socket = socketFeature?.Socket;
        if (socket is null || socket.AddressFamily != AddressFamily.Unix) return null;

        try
        {
            if (OperatingSystem.IsLinux())
            {
                var buf = new byte[12];
                socket.GetRawSocketOption(1, 17, buf);
                return BitConverter.ToInt32(buf, 4);
            }
            if (OperatingSystem.IsMacOS())
            {
                var buf = new byte[76];
                socket.GetRawSocketOption(0, 1, buf);
                return BitConverter.ToInt32(buf, 4);
            }
        }
        catch
        {
            // Platform unsupported or call failed — fall through.
        }
        return null;
    }
}
