using System.Security.Claims;
using NetFirewall.Models.Auth;

namespace NetFirewall.Daemon.Auth;

/// <summary>
/// Enforces the daemon's per-endpoint gates — <see cref="DaemonRequireRootPeerAttribute"/>
/// and <see cref="DaemonRequireElevatedAttribute"/> — for every endpoint that carries them
/// in its metadata.
///
/// <para>Why a middleware: the endpoints are minimal APIs, and minimal APIs never run MVC
/// authorization filters. Before this gate existed both attributes were attached with
/// <c>.WithMetadata(...)</c> and silently ignored: the recovery endpoints (reset password,
/// disable TOTP) answered any accepted peer without a session, and destructive endpoints
/// accepted a non-elevated session of any role.</para>
///
/// <para>Runs after <c>UseAuthorization</c>, so routing has picked the endpoint and
/// <see cref="HttpContext.User"/> is final (session principal or the root-peer principal).</para>
/// </summary>
public sealed class DaemonEndpointGateMiddleware
{
    /// <summary>Roles allowed to run a destructive (elevated) daemon endpoint.</summary>
    private static readonly string[] MutatingRoles = [UserRoles.Admin, UserRoles.Operator];

    private readonly RequestDelegate _next;
    private readonly IPeerUidReader _peerUid;
    private readonly ILogger<DaemonEndpointGateMiddleware> _logger;

    public DaemonEndpointGateMiddleware(
        RequestDelegate next,
        IPeerUidReader peerUid,
        ILogger<DaemonEndpointGateMiddleware> logger)
    {
        _next = next;
        _peerUid = peerUid;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var metadata = context.GetEndpoint()?.Metadata;
        if (metadata is not null)
        {
            var refusal = Evaluate(context, metadata);
            if (refusal is { } r)
            {
                _logger.LogWarning("Daemon gate refused {Method} {Path}: {Error} (user {User})",
                    context.Request.Method, context.Request.Path, r.Error,
                    context.User.Identity?.Name ?? "-");
                context.Response.StatusCode = r.StatusCode;
                await context.Response.WriteAsJsonAsync(new { error = r.Error, message = r.Message },
                    context.RequestAborted);
                return;
            }
        }

        await _next(context);
    }

    internal readonly record struct GateRefusal(int StatusCode, string Error, string Message);

    internal GateRefusal? Evaluate(HttpContext context, EndpointMetadataCollection metadata)
    {
        if (metadata.GetMetadata<DaemonRequireRootPeerAttribute>() is not null)
        {
            var uid = _peerUid.TryGetPeerUid(context);
            if (uid is null)
                return new GateRefusal(StatusCodes.Status403Forbidden, "peer_uid_unavailable",
                    "Recovery endpoints require an identifiable Unix-socket peer (root).");
            if (uid.Value != 0)
                return new GateRefusal(StatusCodes.Status403Forbidden, "root_peer_required",
                    "Recovery operations require running the TUI as root.");
        }

        if (metadata.GetMetadata<DaemonRequireElevatedAttribute>() is not null)
        {
            var user = context.User;
            if (user.Identity?.IsAuthenticated != true)
                return new GateRefusal(StatusCodes.Status401Unauthorized, "unauthenticated",
                    "This operation requires a session.");

            var level = user.FindFirstValue(DaemonSessionAuthHandler.AuthLevelClaim);
            if (!string.Equals(level, AuthLevels.Elevated, StringComparison.OrdinalIgnoreCase))
                return new GateRefusal(StatusCodes.Status403Forbidden, "elevation_required",
                    "This operation requires an elevated session — re-prompt TOTP in the Web.");

            if (!HasMutatingRole(user))
                return new GateRefusal(StatusCodes.Status403Forbidden, "role_forbidden",
                    "This operation requires the Admin or Operator role.");
        }

        return null;
    }

    // Case-insensitive on purpose: user rows carry "admin"/"operator", the root-peer
    // principal (RootPeerBypassMiddleware) carries "Admin".
    private static bool HasMutatingRole(ClaimsPrincipal user) =>
        user.FindAll(ClaimTypes.Role).Any(c =>
            MutatingRoles.Contains(c.Value, StringComparer.OrdinalIgnoreCase));
}
