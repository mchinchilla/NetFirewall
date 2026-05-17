using System.Net.Sockets;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Mvc.Filters;

namespace NetFirewall.Daemon.Auth;

/// <summary>
/// Endpoint-scoped <c>IAuthorizationFilter</c> that short-circuits with
/// <c>Success</c> when the Unix-socket peer UID is 0 (root) — even if the
/// request carries no session token. Used on the Apply* endpoints so a
/// systemd-level <c>netfirewall-bootstrap.service</c> can curl the daemon
/// at boot without holding a user session.
///
/// <para>Other auth filters on the same endpoint (e.g.,
/// <c>[Authorize]</c> from the route group, <c>DaemonRequireElevatedAttribute</c>)
/// run after this one. If we set <c>context.Result</c> to a successful
/// no-op, MVC skips later filters. We don't — we leave the result null,
/// which means: "I have no opinion, let the next filter decide." Then we
/// inject a synthetic <c>ClaimsPrincipal</c> so <c>[Authorize]</c> and
/// elevation gates pass.</para>
///
/// <para>This makes peer-uid==0 effectively equivalent to "fully elevated
/// session". Defensible because: (a) the daemon socket is mode 0660
/// root:netfirewall, so the only way to be uid 0 here is to already be
/// root on the box; (b) being root means you can break everything anyway.
/// Anyone with a regular Web user (netfirewall-web, uid 999) still goes
/// through the full session + elevation flow.</para>
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public sealed class DaemonAllowRootPeerAttribute : Attribute, IAuthorizationFilter, IOrderedFilter
{
    // Run BEFORE the default authorize filter installed by RequireAuthorization()
    // (which has Order=0). Negative Order = earlier execution. Without this,
    // the global filter rejects the request before we get a chance to inject
    // the synthetic principal.
    public int Order => -100;

    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var uid = TryGetPeerUid(context.HttpContext);
        if (uid != 0) return;  // Not root → let other filters decide.

        // Synthesize a fully-authenticated, elevated principal so [Authorize]
        // and DaemonRequireElevatedAttribute pass without modification. The
        // "system-bootstrap" username shows up in audit log entries.
        var identity = new System.Security.Claims.ClaimsIdentity(new[]
        {
            new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Name, "system-bootstrap"),
            new System.Security.Claims.Claim(System.Security.Claims.ClaimTypes.Role, "Admin"),
            new System.Security.Claims.Claim(
                DaemonSessionAuthHandler.AuthLevelClaim,
                NetFirewall.Models.Auth.AuthLevels.Elevated),
        }, authenticationType: "RootPeer");
        context.HttpContext.User = new System.Security.Claims.ClaimsPrincipal(identity);
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
            // Platform unsupported or call failed — treat as not-root.
        }
        return null;
    }
}
