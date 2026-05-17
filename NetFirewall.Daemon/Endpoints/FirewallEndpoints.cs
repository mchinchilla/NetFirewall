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
                IApplyHistoryService history,
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
            // Apply-history feeds the dashboard's "pending changes" detector.
            await history.RecordAsync("nftables", result.Success, result.ExitCode, msg, user.Identity?.Name, ct);

            return result.Success
                ? Results.Json(ServiceResponse<NftApplyDto>.Ok(NftApplyDto.From(result), msg))
                : Results.Json(ServiceResponse<NftApplyDto>.Fail(msg), statusCode: 500);
        })
        .WithMetadata(new DaemonAllowRootPeerAttribute(), new DaemonRequireElevatedAttribute());

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
        .WithMetadata(new DaemonAllowRootPeerAttribute(), new DaemonRequireElevatedAttribute());

        // GET /v1/firewall/policy-routing — read-only listing for the UI (preview).
        grp.MapGet("/policy-routing", async (
                IPolicyRoutingService svc,
                CancellationToken ct) =>
        {
            var tables = await svc.GetRouteTablesAsync(ct);
            var rules = await svc.GetPolicyRulesAsync(ct);
            return Results.Json(ServiceResponse<PolicyRoutingViewDto>.Ok(
                new PolicyRoutingViewDto(tables, rules), "OK"));
        });

        // POST /v1/firewall/apply-policy-routing?dryRun=true — reconcile iproute2
        // with fw_route_tables + fw_policy_rules + fw_static_routes(table_id).
        // Replaces what /root/firewall.sh used to do.
        grp.MapPost("/apply-policy-routing", async (
                IPolicyRoutingApplyService apply,
                IAuthAuditService audit,
                IApplyHistoryService history,
                ClaimsPrincipal user,
                HttpContext ctx,
                bool? dryRun,
                CancellationToken ct) =>
        {
            var isDryRun = dryRun ?? false;
            var result = await apply.ApplyAsync(isDryRun, ct);
            var msg = isDryRun
                ? $"Dry-run produced {result.Steps.Count} step(s) — no kernel changes"
                : (result.Success
                    ? $"Policy routing applied ({result.Steps.Count(s => s.Executed)} command(s))"
                    : result.Error ?? "apply failed");

            await audit.LogAsync(
                isDryRun ? "firewall.apply-routing.dry-run" : "firewall.apply-routing",
                userId: TryUid(user),
                username: user.Identity?.Name,
                ip: ctx.Connection.RemoteIpAddress,
                userAgent: ctx.Request.Headers.UserAgent.ToString(),
                detail: new { result.Success, stepCount = result.Steps.Count, isDryRun },
                ct: ct);

            // Only real runs (not dry-runs) count as "applied" for pending-changes tracking.
            if (!isDryRun)
                await history.RecordAsync("routing", result.Success, null, msg, user.Identity?.Name, ct);

            return result.Success
                ? Results.Json(ServiceResponse<PolicyRoutingApplyResult>.Ok(result, msg))
                : Results.Json(ServiceResponse<PolicyRoutingApplyResult>.Fail(msg), statusCode: 500);
        })
        .WithMetadata(new DaemonAllowRootPeerAttribute(), new DaemonRequireElevatedAttribute());

        grp.MapPost("/apply-qos", async (
                ITcApplyService tc,
                IAuthAuditService audit,
                IApplyHistoryService history,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            var result = await tc.ApplyAsync(ct);
            var msg = result.Success
                ? $"tc/HTB hierarchy applied (exit {result.ExitCode})"
                : (string.IsNullOrEmpty(result.Error) ? $"tc apply failed (exit {result.ExitCode})" : result.Error.Trim());

            await audit.LogAsync(
                "firewall.apply-qos",
                userId: TryUid(user),
                username: user.Identity?.Name,
                ip: ctx.Connection.RemoteIpAddress,
                userAgent: ctx.Request.Headers.UserAgent.ToString(),
                detail: new { success = result.Success, exit = result.ExitCode, error = result.Error },
                ct: ct);
            await history.RecordAsync("tc", result.Success, result.ExitCode, msg, user.Identity?.Name, ct);

            return result.Success
                ? Results.Json(ServiceResponse<NftApplyDto>.Ok(NftApplyDto.From(result), msg))
                : Results.Json(ServiceResponse<NftApplyDto>.Fail(msg), statusCode: 500);
        })
        .WithMetadata(new DaemonAllowRootPeerAttribute(), new DaemonRequireElevatedAttribute());
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

    public sealed record PolicyRoutingViewDto(
        IReadOnlyList<NetFirewall.Models.Firewall.FwRouteTable> Tables,
        IReadOnlyList<NetFirewall.Models.Firewall.FwPolicyRule> Rules);
}
