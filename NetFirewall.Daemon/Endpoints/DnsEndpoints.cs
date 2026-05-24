using System.Security.Claims;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Daemon.Auth;
using NetFirewall.Models;
using NetFirewall.Models.Network;
using NetFirewall.Models.System;
using NetFirewall.Services.Auth;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;

namespace NetFirewall.Daemon.Endpoints;

/// <summary>
/// DNS forwarder control plane. The wizard's Step 4 posts a
/// <see cref="DnsForwarderConfig"/> here so the daemon writes
/// <c>/etc/unbound/unbound.conf.d/netfirewall.conf</c> and restarts unbound.
/// </summary>
public static class DnsEndpoints
{
    public static void MapDnsEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/v1/dns").RequireAuthorization();

        // POST /v1/dns/apply — render unbound conf + restart service.
        // Elevation required: writing /etc/unbound and restarting the service
        // are both destructive and need a fresh TOTP step-up.
        grp.MapPost("/apply", async (
                [FromBody] DnsForwarderConfig config,
                IDnsForwarderService dns,
                IAuthAuditService audit,
                IApplyHistoryService history,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            var envelope = await dns.ApplyAsync(config, ct);

            await audit.LogAsync(
                "dns.apply",
                userId: TryGetUserId(user),
                username: user.Identity?.Name,
                ip: ctx.Connection.RemoteIpAddress,
                userAgent: ctx.Request.Headers.UserAgent.ToString(),
                detail: new
                {
                    enabled = config.Enabled,
                    success = envelope.Success,
                    exit = envelope.Data?.ExitCode ?? -1,
                    message = envelope.Message
                },
                ct: ct);

            await history.RecordAsync(
                kind: "dns",
                success: envelope.Success,
                exitCode: envelope.Data?.ExitCode ?? -1,
                message: envelope.Message ?? string.Empty,
                appliedBy: user.Identity?.Name,
                ct: ct);

            return envelope.Success
                ? Results.Json(envelope)
                : Results.Json(envelope, statusCode: 500);
        })
        .WithMetadata(new DaemonRequireElevatedAttribute());
    }

    private static Guid? TryGetUserId(ClaimsPrincipal user)
        => Guid.TryParse(user.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : null;
}
