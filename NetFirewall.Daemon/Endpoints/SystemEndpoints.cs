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

        // GET /v1/system/wan-health — current per-WAN health state + recent
        // transitions + the control row (active WAN + manual override).
        grp.MapGet("/wan-health", async (
                NetFirewall.Services.WanMonitor.IWanHealthService wan,
                CancellationToken ct) =>
        {
            var state = await wan.GetStateAsync(ct);
            var events = await wan.RecentEventsAsync(20, ct);
            var control = await wan.GetControlAsync(ct);
            return Results.Json(ServiceResponse<WanHealthDto>.Ok(new WanHealthDto(state, events, control), "OK"));
        });

        // POST /v1/system/wan-failover — manually pin a WAN as the active default
        // route (sticky override). Elevated + destructive (mutates routing).
        grp.MapPost("/wan-failover", async (
                WanFailoverRequest req,
                NetFirewall.Services.WanMonitor.IWanFailoverControlService ctrl,
                System.Security.Claims.ClaimsPrincipal user,
                CancellationToken ct) =>
        {
            if (req.InterfaceId == Guid.Empty)
                return Results.Json(ServiceResponse<bool>.Fail("interfaceId is required."));
            var res = await ctrl.ForceActiveAsync(req.InterfaceId, user.Identity?.Name, ct);
            return Results.Json(res, statusCode: res.Success ? 200 : 500);
        })
        .WithMetadata(new NetFirewall.Daemon.Auth.DaemonAllowRootPeerAttribute(),
                      new NetFirewall.Daemon.Auth.DaemonRequireElevatedAttribute());

        // POST /v1/system/wan-failover/clear — drop the manual override, return
        // to automatic priority-based failover.
        grp.MapPost("/wan-failover/clear", async (
                NetFirewall.Services.WanMonitor.IWanFailoverControlService ctrl,
                System.Security.Claims.ClaimsPrincipal user,
                CancellationToken ct) =>
        {
            var res = await ctrl.ClearOverrideAsync(user.Identity?.Name, ct);
            return Results.Json(res, statusCode: res.Success ? 200 : 500);
        })
        .WithMetadata(new NetFirewall.Daemon.Auth.DaemonAllowRootPeerAttribute(),
                      new NetFirewall.Daemon.Auth.DaemonRequireElevatedAttribute());

        // GET /v1/system/vpn-health — per-peer WireGuard health state, recent
        // transitions, and the currently-active alerts that feed the UI banner.
        grp.MapGet("/vpn-health", async (
                NetFirewall.Services.Vpn.IVpnHealthService vpn,
                CancellationToken ct) =>
        {
            var state = await vpn.GetStateAsync(ct);
            var events = await vpn.RecentEventsAsync(20, ct);
            var alerts = await vpn.ActiveAlertsAsync(ct);
            return Results.Json(ServiceResponse<VpnHealthDto>.Ok(new VpnHealthDto(state, events, alerts), "OK"));
        });

        // GET /v1/system/alerts?limit=50 — recent system alerts (active + resolved),
        // the unified activity feed across VPN, WAN failover, etc. Powers the
        // notifications dropdown and the "View all activity" history page.
        grp.MapGet("/alerts", async (
                NetFirewall.Services.Vpn.IVpnHealthService vpn,
                int? limit,
                CancellationToken ct) =>
        {
            var n = Math.Clamp(limit ?? 50, 1, 200);
            var alerts = await vpn.RecentAlertsAsync(n, ct);
            return Results.Json(ServiceResponse<AlertsDto>.Ok(new AlertsDto(alerts), "OK"));
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

        // GET /v1/system/top-talkers/host/{srcIp}/destinations?hours=24&limit=10
        // — the per-destination drill-down for one LAN host, ASN-enriched.
        grp.MapGet("/top-talkers/host/{srcIp}/destinations", async (
                ITopTalkersService svc,
                string srcIp,
                int? hours,
                int? limit,
                CancellationToken ct) =>
        {
            if (!System.Net.IPAddress.TryParse(srcIp, out var ip))
                return Results.Json(ServiceResponse<HostDestinationsDto>.Fail("Invalid source IP"));

            var h = Math.Clamp(hours ?? 24, 1, 168);
            var n = Math.Clamp(limit ?? 10, 1, 50);
            var rows = await svc.GetTopDestinationsForHostAsync(ip, h, n, ct);
            return Results.Json(ServiceResponse<HostDestinationsDto>.Ok(
                new HostDestinationsDto(ip, rows), "OK"));
        });

        // GET /v1/system/top-destinations?hours=24&limit=8 — busiest destinations
        // across the whole LAN, ASN-enriched. Powers the home dashboard panel.
        grp.MapGet("/top-destinations", async (
                ITopTalkersService svc,
                int? hours,
                int? limit,
                CancellationToken ct) =>
        {
            var h = Math.Clamp(hours ?? 24, 1, 168);
            var n = Math.Clamp(limit ?? 8, 1, 50);
            var rows = await svc.GetTopDestinationsGlobalAsync(h, n, ct);
            return Results.Json(ServiceResponse<TopDestinationsDto>.Ok(new TopDestinationsDto(rows), "OK"));
        });
    }

    public sealed record HostDestinationsDto(
        System.Net.IPAddress SrcIp,
        IReadOnlyList<TopTalkerDestination> Destinations);

    public sealed record TopDestinationsDto(
        IReadOnlyList<TopTalkerDestination> Destinations);

    public sealed record TopTalkersDto(
        IReadOnlyList<TopTalkerHost> Hosts,
        IReadOnlyList<TopTalkerService> Services);

    public sealed record WanHealthDto(
        IReadOnlyList<NetFirewall.Models.WanMonitor.WanHealthState> State,
        IReadOnlyList<NetFirewall.Models.WanMonitor.WanHealthEvent> RecentEvents,
        NetFirewall.Models.WanMonitor.WanFailoverControl Control);

    public sealed record WanFailoverRequest(Guid InterfaceId);

    public sealed record AlertsDto(
        IReadOnlyList<NetFirewall.Models.Vpn.SystemAlert> Alerts);

    public sealed record VpnHealthDto(
        IReadOnlyList<NetFirewall.Models.Vpn.VpnHealthState> State,
        IReadOnlyList<NetFirewall.Models.Vpn.VpnHealthEvent> RecentEvents,
        IReadOnlyList<NetFirewall.Models.Vpn.SystemAlert> ActiveAlerts);
}
