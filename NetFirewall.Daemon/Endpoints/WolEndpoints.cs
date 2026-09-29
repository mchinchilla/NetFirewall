using System.Security.Claims;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Wol;
using NetFirewall.Services.Auth;
using NetFirewall.Services.Wol;

namespace NetFirewall.Daemon.Endpoints;

/// <summary>
/// Wake-on-LAN. The daemon sends because the packet must leave through a chosen
/// LAN link (<c>SO_BINDTODEVICE</c>) — the Web, with zero capabilities and no
/// say over routing, only asks. A wake changes no state on the box, so Admin and
/// Operator may send one without step-up; every attempt is audited either way.
/// </summary>
public static class WolEndpoints
{
    public static void MapWolEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/v1/wol")
            .RequireAuthorization(p => p.RequireRole(UserRoles.Admin, UserRoles.Operator));

        grp.MapPost("/wake", async (
                WolWakeRequest req,
                IWakeOnLanService wol,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            var env = await wol.WakeAsync(req, ct);

            try
            {
                await audit.LogAsync(
                    env.Success ? AuthAuditEvents.WolSent : AuthAuditEvents.WolFailed,
                    userId: Guid.TryParse(user.FindFirstValue(ClaimTypes.NameIdentifier), out var uid) ? uid : null,
                    username: user.Identity?.Name,
                    ip: ctx.Connection.RemoteIpAddress,
                    userAgent: ctx.Request.Headers.UserAgent.ToString(),
                    detail: new
                    {
                        mac = env.Data?.Mac ?? req.Mac,
                        iface = env.Data?.Interface ?? req.Interface,
                        via = env.Data?.InterfaceSource,
                        ipHint = req.IpHint,
                        port = env.Data?.Port ?? req.Port,
                        message = env.Success ? null : env.Message,
                    },
                    ct: ct);
            }
            catch
            {
                // The packet is already on the wire (or already refused); an audit
                // hiccup must not turn that into an error the operator retries.
            }

            return Results.Json(env, statusCode: env.Success ? 200 : 400);
        });
    }
}
