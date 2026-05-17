using NetFirewall.Models;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Monitoring;

namespace NetFirewall.Daemon.Endpoints;

/// <summary>
/// Dashboard-supporting endpoints. Read-only, no elevation, no destructive
/// operations. Designed to be called every page refresh of /Home/Index.
/// </summary>
public static class SystemEndpoints
{
    public static void MapSystemEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/v1/system").RequireAuthorization();

        // GET /v1/system/services — systemctl status for each watched unit.
        grp.MapGet("/services", async (ISystemServiceHealthService health, CancellationToken ct) =>
        {
            var list = await health.GetAllAsync(ct);
            return Results.Json(ServiceResponse<IReadOnlyList<ServiceHealth>>.Ok(list));
        });

        // GET /v1/system/wan-status — ping each WAN gateway and report.
        grp.MapGet("/wan-status", async (IWanReachabilityService wan, CancellationToken ct) =>
        {
            var list = await wan.ProbeAllAsync(ct);
            return Results.Json(ServiceResponse<IReadOnlyList<WanReachability>>.Ok(list));
        });

        // GET /v1/system/pending-changes — DB rows changed since last successful Apply,
        // grouped by Apply kind (nftables / tc / wireguard).
        grp.MapGet("/pending-changes", async (IApplyHistoryService history, CancellationToken ct) =>
        {
            var list = await history.GetPendingSummaryAsync(ct);
            return Results.Json(ServiceResponse<IReadOnlyList<PendingChangesSummary>>.Ok(list));
        });

        // GET /v1/system/apply-history?limit=10 — last N apply attempts.
        grp.MapGet("/apply-history", async (IApplyHistoryService history, int? limit, CancellationToken ct) =>
        {
            var list = await history.RecentAsync(limit ?? 10, ct);
            return Results.Json(ServiceResponse<IReadOnlyList<ApplyHistoryEntry>>.Ok(list));
        });

        // GET /v1/system/wan-health — current per-WAN health state + recent transitions.
        grp.MapGet("/wan-health", async (
                NetFirewall.Services.WanMonitor.IWanHealthService wan,
                CancellationToken ct) =>
        {
            var state = await wan.GetStateAsync(ct);
            var events = await wan.RecentEventsAsync(20, ct);
            return Results.Json(ServiceResponse<WanHealthDto>.Ok(new WanHealthDto(state, events), "OK"));
        });

        // GET /v1/system/top-talkers?hours=24&limit=5 — top hosts + services.
        grp.MapGet("/top-talkers", async (
                ITopTalkersService svc,
                int? hours,
                int? limit,
                CancellationToken ct) =>
        {
            var h = Math.Clamp(hours ?? 24, 1, 168);  // 1h .. 7d
            var n = Math.Clamp(limit ?? 5, 1, 50);
            var hostsTask    = svc.GetTopHostsAsync(h, n, ct);
            var servicesTask = svc.GetTopServicesAsync(h, n, ct);
            await Task.WhenAll(hostsTask, servicesTask);
            return Results.Json(ServiceResponse<TopTalkersDto>.Ok(
                new TopTalkersDto(hostsTask.Result, servicesTask.Result), "OK"));
        });
    }

    public sealed record TopTalkersDto(
        IReadOnlyList<TopTalkerHost> Hosts,
        IReadOnlyList<TopTalkerService> Services);

    public sealed record WanHealthDto(
        IReadOnlyList<NetFirewall.Models.WanMonitor.WanHealthState> State,
        IReadOnlyList<NetFirewall.Models.WanMonitor.WanHealthEvent> RecentEvents);
}
