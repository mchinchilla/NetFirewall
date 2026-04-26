using System.Security.Claims;
using NetFirewall.Daemon.Auth;
using NetFirewall.Models;
using NetFirewall.Models.System;
using NetFirewall.Services.Auth;
using NetFirewall.Services.Network;

namespace NetFirewall.Daemon.Endpoints;

public static class RouteEndpoints
{
    public static void MapRouteEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/v1/routes").RequireAuthorization();

        grp.MapPost("/{id:guid}/apply", async (
                Guid id,
                IStaticRouteApplicator applicator,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            var envelope = await applicator.ApplyAsync(id, ct);
            await LogAsync(audit, "route.apply", user, ctx, id, envelope, ct);
            return envelope.Success
                ? Results.Json(envelope)
                : Results.Json(envelope, statusCode: 500);
        })
        .WithMetadata(new DaemonRequireElevatedAttribute());

        grp.MapPost("/{id:guid}/remove", async (
                Guid id,
                IStaticRouteApplicator applicator,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            var envelope = await applicator.RemoveAsync(id, ct);
            await LogAsync(audit, "route.remove", user, ctx, id, envelope, ct);
            return envelope.Success
                ? Results.Json(envelope)
                : Results.Json(envelope, statusCode: 500);
        })
        .WithMetadata(new DaemonRequireElevatedAttribute());
    }

    private static async Task LogAsync(
        IAuthAuditService audit,
        string evt,
        ClaimsPrincipal user,
        HttpContext ctx,
        Guid routeId,
        ServiceResponse<NetworkApplyResult> envelope,
        CancellationToken ct)
    {
        Guid? uid = Guid.TryParse(user.FindFirstValue(ClaimTypes.NameIdentifier), out var v) ? v : null;
        await audit.LogAsync(
            evt,
            userId: uid,
            username: user.Identity?.Name,
            ip: ctx.Connection.RemoteIpAddress,
            userAgent: ctx.Request.Headers.UserAgent.ToString(),
            detail: new { routeId, success = envelope.Success, message = envelope.Message },
            ct: ct);
    }
}
