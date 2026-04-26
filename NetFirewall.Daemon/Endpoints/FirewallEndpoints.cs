using System.Security.Claims;
using NetFirewall.Daemon.Auth;
using NetFirewall.Models;
using NetFirewall.Services.Auth;
using NetFirewall.Services.Firewall;

namespace NetFirewall.Daemon.Endpoints;

/// <summary>
/// nftables apply endpoints. Generation of the config is local to the Web
/// (no privilege needed — pure string-build over the DB), but writing to
/// <c>/etc/nftables.conf</c> and running <c>nft -f</c> requires CAP_NET_ADMIN —
/// which only the daemon has.
/// </summary>
public static class FirewallEndpoints
{
    public static void MapFirewallEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/v1/firewall").RequireAuthorization();

        grp.MapPost("/apply", async (
                INftApplyService nft,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            var result = await nft.ApplyConfigurationAsync(ct);
            var msg = SummariseResult(result);

            await audit.LogAsync(
                "firewall.apply",
                userId: TryUid(user),
                username: user.Identity?.Name,
                ip: ctx.Connection.RemoteIpAddress,
                userAgent: ctx.Request.Headers.UserAgent.ToString(),
                detail: new { success = result.Success, exit = result.ExitCode, error = result.Error, backupPath = result.BackupPath },
                ct: ct);

            return result.Success
                ? Results.Json(ServiceResponse<NftApplyDto>.Ok(NftApplyDto.From(result), msg))
                : Results.Json(ServiceResponse<NftApplyDto>.Fail(msg), statusCode: 500);
        })
        .WithMetadata(new DaemonRequireElevatedAttribute());

        grp.MapPost("/validate", async (
                ValidateRequest req,
                INftApplyService nft,
                CancellationToken ct) =>
        {
            var result = await nft.ValidateConfigurationAsync(req.Config ?? string.Empty, ct);
            var msg = SummariseResult(result);
            return Results.Json(result.Success
                ? ServiceResponse<NftApplyDto>.Ok(NftApplyDto.From(result), msg)
                : ServiceResponse<NftApplyDto>.Fail(msg));
        });

        grp.MapGet("/current-ruleset", async (INftApplyService nft, CancellationToken ct) =>
        {
            var current = await nft.GetCurrentRulesetAsync(ct);
            return Results.Text(current);
        });

        grp.MapPost("/backup", async (
                INftApplyService nft,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            var path = await nft.BackupCurrentRulesetAsync(ct);
            await audit.LogAsync(
                "firewall.backup",
                userId: TryUid(user),
                username: user.Identity?.Name,
                ip: ctx.Connection.RemoteIpAddress,
                userAgent: ctx.Request.Headers.UserAgent.ToString(),
                detail: new { path },
                ct: ct);
            return Results.Json(ServiceResponse<string>.Ok(path, "Ruleset backed up."));
        })
        .WithMetadata(new DaemonRequireElevatedAttribute());
    }

    private static Guid? TryUid(ClaimsPrincipal user)
        => Guid.TryParse(user.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : null;

    private static string SummariseResult(NftApplyResult r) =>
        r.Success
            ? $"nftables ruleset applied (exit {r.ExitCode})"
            : (string.IsNullOrEmpty(r.Error) ? $"nftables apply failed (exit {r.ExitCode})" : r.Error.Trim());

    public sealed record ValidateRequest(string? Config);

    public sealed record NftApplyDto(int ExitCode, string? BackupPath, string? Output, string? Error)
    {
        public static NftApplyDto From(NftApplyResult r) =>
            new(r.ExitCode, r.BackupPath, r.Output, r.Error);
    }
}
