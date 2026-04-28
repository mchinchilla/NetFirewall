using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Daemon.Auth;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.System;
using NetFirewall.Services.Auth;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;

namespace NetFirewall.Daemon.Endpoints;

public static class NetworkEndpoints
{
    public static void MapNetworkEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/v1/network").RequireAuthorization();

        // GET /v1/network/interfaces — list all configured fw_interfaces rows.
        // No elevation: read-only. Used by the TUI to render the picker.
        grp.MapGet("/interfaces", async (
                IFirewallService firewall,
                CancellationToken ct) =>
        {
            var list = await firewall.GetInterfacesAsync(ct);
            return Results.Json(ServiceResponse<IReadOnlyList<FwInterface>>.Ok(list));
        });

        // GET /v1/network/interfaces/discover — physical interfaces present on
        // the host (NICs the kernel sees) with type/role suggestions. The TUI
        // shows this when the user picks "Add new interface" so they don't
        // have to remember whether their NIC is named eth0 or enp0s3.
        grp.MapGet("/interfaces/discover", async (
                ILinuxDistroService distro,
                CancellationToken ct) =>
        {
            var found = await distro.DiscoverInterfacesAsync(ct);
            return Results.Json(ServiceResponse<IReadOnlyList<InterfaceSuggestion>>.Ok(found));
        });

        // POST /v1/network/interfaces — create a new fw_interfaces row.
        // Elevated: this is destructive (admin can create a phantom interface
        // pointing at any IP). TUI sessions are born elevated so this just
        // works after login.
        grp.MapPost("/interfaces", async (
                [FromBody] FwInterface body,
                IFirewallService firewall,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            var created = await firewall.CreateInterfaceAsync(body, ct);
            await audit.LogAsync(
                "network.interface.create",
                userId: TryGetUserId(user),
                username: user.Identity?.Name,
                ip: ctx.Connection.RemoteIpAddress,
                userAgent: ctx.Request.Headers.UserAgent.ToString(),
                detail: new { created.Id, created.Name, created.Type, created.IpAddress },
                ct: ct);
            return Results.Json(ServiceResponse<FwInterface>.Ok(created, "Interface created."));
        })
        .WithMetadata(new DaemonRequireElevatedAttribute());

        // PUT /v1/network/interfaces/{id} — update IP/mask/gateway/MAC etc.
        // Same elevation reason as POST.
        grp.MapPut("/interfaces/{id:guid}", async (
                Guid id,
                [FromBody] FwInterface body,
                IFirewallService firewall,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            // The route's id wins over whatever the body claims — defensive
            // against a client that posts a stale or wrong Id.
            body.Id = id;
            var updated = await firewall.UpdateInterfaceAsync(body, ct);
            await audit.LogAsync(
                "network.interface.update",
                userId: TryGetUserId(user),
                username: user.Identity?.Name,
                ip: ctx.Connection.RemoteIpAddress,
                userAgent: ctx.Request.Headers.UserAgent.ToString(),
                detail: new { updated.Id, updated.Name, updated.IpAddress, updated.SubnetMask, updated.Gateway, updated.MacAddress },
                ct: ct);
            return Results.Json(ServiceResponse<FwInterface>.Ok(updated, "Interface updated."));
        })
        .WithMetadata(new DaemonRequireElevatedAttribute());

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
