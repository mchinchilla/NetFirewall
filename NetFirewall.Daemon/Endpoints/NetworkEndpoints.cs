using System.Net;
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
                INetworkConfigResolver configResolver,
                CancellationToken ct) =>
        {
            var found = await distro.DiscoverInterfacesAsync(ct);

            // Enrich with the DECLARED addressing mode (dhcp/static) read from the
            // system network config — the daemon runs as root and can read
            // /etc/network/interfaces / netplan / nmcli. The wizard prefers this
            // over its WAN+gateway heuristic (which got ens192/ens224 backwards).
            try
            {
                var cfg = await configResolver.ResolveAsync(ct);
                foreach (var s in found)
                    s.AddressingMode = await cfg.DetectAddressingModeAsync(s.Name, ct);
            }
            catch
            {
                // Best-effort: if mode detection fails, leave it null and the
                // wizard falls back to its heuristic. Never fail discovery over it.
            }

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

        // POST /v1/network/interfaces/redetect — walk /sys/class/net, reconcile
        // each detected NIC against fw_interfaces. For existing rows: refresh
        // ip/mask/gateway/mac/mtu from the OS (preserving operator-edited
        // type/role/description/addressing_mode/vlan/enabled). For new NICs:
        // insert with detected values + suggested type/role. Demoted rows are
        // not deleted — they're reported as "missing" so the operator decides.
        //
        // Non-elevated: read-only against the OS, idempotent upsert against
        // the DB. Available during bootstrap so the seed never wins over reality.
        grp.MapPost("/interfaces/redetect", async (
                ILinuxDistroService distro,
                IFirewallService firewall,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            var detected = await distro.DiscoverInterfacesAsync(ct);
            var configured = await firewall.GetInterfacesAsync(ct);
            var byName = configured.ToDictionary(c => c.Name, StringComparer.OrdinalIgnoreCase);

            var result = new RedetectResult();

            foreach (var d in detected)
            {
                var detectedMask = ParseMaskFromCidr(d.CurrentSubnet);

                if (byName.TryGetValue(d.Name, out var existing))
                {
                    var ipChanged       = !Equals(existing.IpAddress?.ToString(), d.CurrentIp?.ToString());
                    var maskChanged     = !Equals(existing.SubnetMask?.ToString(), detectedMask?.ToString());
                    var gatewayChanged  = !Equals(existing.Gateway?.ToString(), d.CurrentGateway?.ToString());
                    var macChanged      = !Equals(existing.MacAddress, d.MacAddress);
                    var mtuChanged      = existing.Mtu != d.Mtu;

                    if (ipChanged || maskChanged || gatewayChanged || macChanged || mtuChanged)
                    {
                        existing.IpAddress  = d.CurrentIp;
                        existing.SubnetMask = detectedMask;
                        existing.Gateway    = d.CurrentGateway;
                        existing.MacAddress = d.MacAddress;
                        existing.Mtu        = d.Mtu;
                        await firewall.UpdateInterfaceAsync(existing, ct);
                        result.Updated++;
                        if (ipChanged || gatewayChanged) result.Changed.Add(d.Name);
                    }
                }
                else
                {
                    var inserted = new FwInterface
                    {
                        Name        = d.Name,
                        Type        = string.IsNullOrEmpty(d.SuggestedType) ? "LAN" : d.SuggestedType,
                        Role        = string.IsNullOrEmpty(d.SuggestedRole) ? null : d.SuggestedRole,
                        IpAddress   = d.CurrentIp,
                        SubnetMask  = detectedMask,
                        Gateway     = d.CurrentGateway,
                        MacAddress  = d.MacAddress,
                        Mtu         = d.Mtu,
                        AddressingMode = "static",
                        Enabled     = d.IsUp,
                        AutoStart   = true
                    };
                    await firewall.CreateInterfaceAsync(inserted, ct);
                    result.Added++;
                }
            }

            // Rows in the DB whose NIC the kernel no longer sees.
            var detectedNames = detected.Select(d => d.Name).ToHashSet(StringComparer.OrdinalIgnoreCase);
            result.Missing = configured.Count(c => !detectedNames.Contains(c.Name));

            await audit.LogAsync(
                "network.interface.redetect",
                userId: TryGetUserId(user),
                username: user.Identity?.Name,
                ip: ctx.Connection.RemoteIpAddress,
                userAgent: ctx.Request.Headers.UserAgent.ToString(),
                detail: new { result.Added, result.Updated, result.Missing, changed = result.Changed },
                ct: ct);

            return Results.Json(ServiceResponse<RedetectResult>.Ok(result, "Interfaces reconciled."));
        });

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

    /// <summary>
    /// Given a CIDR string like "192.168.99.1/24", return the netmask
    /// (255.255.255.0) so we can store it in fw_interfaces.subnet_mask.
    /// fw_interfaces stores the mask as an inet (dotted-quad) for IPv4
    /// compatibility with the legacy schema.
    /// </summary>
    private static IPAddress? ParseMaskFromCidr(string? cidr)
    {
        if (string.IsNullOrWhiteSpace(cidr)) return null;
        var slash = cidr.IndexOf('/');
        if (slash < 0 || !int.TryParse(cidr.AsSpan(slash + 1), out var prefix)) return null;
        if (prefix < 0 || prefix > 32) return null;
        // 24-bit prefix → 0xFFFFFF00 → 255.255.255.0
        uint maskInt = prefix == 0 ? 0u : 0xFFFFFFFFu << (32 - prefix);
        var bytes = new[] { (byte)(maskInt >> 24), (byte)(maskInt >> 16), (byte)(maskInt >> 8), (byte)maskInt };
        return new IPAddress(bytes);
    }

    public sealed record NetworkApplyResultDto(string? FilePath, string? Backup, int ExitCode, string? Output, string? Error)
    {
        public static NetworkApplyResultDto From(NetFirewall.Models.System.NetworkApplyResult r) =>
            new(r.ConfigFilePath, r.BackupFilePath, r.ExitCode, r.Output, r.ErrorOutput);
    }
}
