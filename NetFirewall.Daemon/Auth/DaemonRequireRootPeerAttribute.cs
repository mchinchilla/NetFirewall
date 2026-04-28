using System.Net.Sockets;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace NetFirewall.Daemon.Auth;

/// <summary>
/// Per-endpoint gate: only accepts requests whose Unix-socket peer UID is 0
/// (root). Used by recovery endpoints which must remain reachable when the
/// session-based auth path is blocked (locked-out admin, lost TOTP, etc.) —
/// they intentionally bypass <c>X-NetFw-Session</c> and rely on physical
/// console access via sudo as the sole credential.
///
/// <para>This attribute is independent of the global
/// <see cref="PeerCredentialMiddleware"/>: that middleware enforces a single
/// configured UID for the whole socket; this attribute enforces UID==0
/// specifically for the decorated endpoints. Both must pass — production
/// deployments that pin a non-root <c>ExpectedPeerUid</c> on the global
/// middleware will need to either accept multiple UIDs or run the TUI under
/// the same UID for recovery to be reachable. Documented in deploy/README.</para>
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public sealed class DaemonRequireRootPeerAttribute : Attribute, IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        var uid = TryGetPeerUid(context.HttpContext);
        if (uid is null)
        {
            // Couldn't read peer credentials — refuse rather than fall open.
            // Happens on platforms that don't expose SO_PEERCRED, or on
            // non-Unix transports (which this daemon doesn't bind anyway).
            context.Result = new ObjectResult(new
            {
                error = "peer_uid_unavailable",
                message = "Recovery endpoints require an identifiable Unix-socket peer (root)."
            }) { StatusCode = StatusCodes.Status403Forbidden };
            return;
        }

        if (uid.Value != 0)
        {
            context.Result = new ObjectResult(new
            {
                error = "root_peer_required",
                message = "Recovery operations require running the TUI as root (use sudo)."
            }) { StatusCode = StatusCodes.Status403Forbidden };
            return;
        }
    }

    /// <summary>
    /// Read the peer UID via SO_PEERCRED-style APIs. Mirrors the helper in
    /// <see cref="PeerCredentialMiddleware"/> — duplicated rather than refactored
    /// because the only sane shared interface here is "give me an int?", and
    /// pulling it out adds a layer of indirection that hides the platform check.
    /// </summary>
    private static int? TryGetPeerUid(HttpContext context)
    {
        var socketFeature = context.Features.Get<IConnectionSocketFeature>();
        var socket = socketFeature?.Socket;
        if (socket is null || socket.AddressFamily != AddressFamily.Unix) return null;

        try
        {
            if (OperatingSystem.IsLinux())
            {
                // Linux: SOL_SOCKET (1) + SO_PEERCRED (17) → ucred { pid, uid, gid }
                var buf = new byte[12];
                socket.GetRawSocketOption(1, 17, buf);
                return BitConverter.ToInt32(buf, 4);
            }
            if (OperatingSystem.IsMacOS())
            {
                // macOS: SOL_LOCAL (0) + LOCAL_PEERCRED (1) → xucred (uid at offset 4)
                var buf = new byte[76];
                socket.GetRawSocketOption(0, 1, buf);
                return BitConverter.ToInt32(buf, 4);
            }
        }
        catch
        {
            // Platform doesn't support the option, or the call failed — treat as missing.
        }
        return null;
    }
}
