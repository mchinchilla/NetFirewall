using System.Security.Claims;
using NetFirewall.Daemon.Auth;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Auth;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;

namespace NetFirewall.Daemon.Endpoints;

public static class NetworkEndpoints
{
    public static void MapNetworkEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/v1/network").RequireAuthorization();

        // POST /v1/network/{id:guid}/apply — write the iface config + bring up.
        grp.MapPost("/{id:guid}/apply", async (
                Guid id,
                IFirewallService firewall,
                INetworkConfigResolver resolver,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            var iface = await firewall.GetInterfaceByIdAsync(id, ct);
            if (iface is null)
                return Results.Json(ServiceResponse<object>.Fail("Interface not found."), statusCode: 404);

            var routes = (await firewall.GetStaticRoutesAsync(id, ct)).Where(r => r.Enabled).ToList();
            var writer = await resolver.ResolveAsync(ct);
            var result = await writer.ApplyConfigAsync(iface, routes);

            await audit.LogAsync(
                "network.apply",
                userId: TryGetUserId(user),
                username: user.Identity?.Name,
                ip: ctx.Connection.RemoteIpAddress,
                userAgent: ctx.Request.Headers.UserAgent.ToString(),
                detail: new { iface = iface.Name, success = result.Success, exit = result.ExitCode, message = result.Message },
                ct: ct);

            return result.Success
                ? Results.Json(ServiceResponse<NetworkApplyResultDto>.Ok(NetworkApplyResultDto.From(result), result.Message))
                : Results.Json(ServiceResponse<NetworkApplyResultDto>.Fail(result.Message), statusCode: 500);
        })
        .WithMetadata(new DaemonRequireElevatedAttribute());

        // POST /v1/network/restart — restart networking subsystem.
        grp.MapPost("/restart", async (
                INetworkConfigResolver resolver,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            var writer = await resolver.ResolveAsync(ct);
            var result = await writer.RestartNetworkingAsync();

            await audit.LogAsync(
                "network.restart",
                userId: TryGetUserId(user),
                username: user.Identity?.Name,
                ip: ctx.Connection.RemoteIpAddress,
                userAgent: ctx.Request.Headers.UserAgent.ToString(),
                detail: new { success = result.Success, exit = result.ExitCode, message = result.Message },
                ct: ct);

            return result.Success
                ? Results.Json(ServiceResponse<NetworkApplyResultDto>.Ok(NetworkApplyResultDto.From(result), result.Message))
                : Results.Json(ServiceResponse<NetworkApplyResultDto>.Fail(result.Message), statusCode: 500);
        })
        .WithMetadata(new DaemonRequireElevatedAttribute());
    }

    private static Guid? TryGetUserId(ClaimsPrincipal user)
        => Guid.TryParse(user.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : null;

    public sealed record NetworkApplyResultDto(string? FilePath, string? Backup, int ExitCode, string? Output, string? Error)
    {
        public static NetworkApplyResultDto From(NetFirewall.Models.System.NetworkApplyResult r) =>
            new(r.ConfigFilePath, r.BackupFilePath, r.ExitCode, r.Output, r.ErrorOutput);
    }
}
