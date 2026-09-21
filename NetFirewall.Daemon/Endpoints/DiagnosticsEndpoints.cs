using System.Security.Claims;
using NetFirewall.Daemon.Auth;
using Microsoft.Extensions.Options;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Auth;
using NetFirewall.Services.Diagnostics;
using NetFirewall.Services.Diagnostics.Doctors;
using NetFirewall.Services.Diagnostics.Jobs;
using NetFirewall.Services.Firewall;

namespace NetFirewall.Daemon.Endpoints;

/// <summary>
/// Diagnostics tools (see docs/diagnostics.md). Everything here is READ-ONLY on
/// the box — probes and lookups, no kernel mutation — so Admin and Operator may
/// run them without step-up. Phase 2 adds an Admin + elevated subgroup for the
/// invasive tools (nft trace rule insertion, packet capture).
///
/// Every POST goes through <see cref="IDiagnosticRunner"/>: gate slot → diag_runs
/// row → budgeted body → row closed → envelope, and is audited as diag.run
/// (diag.denied when the gate refused). The GET panels (interface health,
/// neighbours, sysctl) are live views polled by the UI and are NOT persisted.
///
/// Inputs are re-validated here even though the Web validated them already:
/// the daemon never trusts its caller with anything that ends up in argv.
/// </summary>
public static class DiagnosticsEndpoints
{
    private static readonly HashSet<string> DropLogFilters = new(StringComparer.Ordinal) { "drops", "martians", "wg", "all" };

    public static void MapDiagnosticsEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/v1/diagnostics")
            .RequireAuthorization(p => p.RequireRole(UserRoles.Admin, UserRoles.Operator));

        // ───────────────────────── ping ─────────────────────────
        grp.MapPost("/ping", async (
                PingRequest req,
                IDiagnosticInputValidator v,
                IPingProbeService ping,
                IInterfaceHealthService ifaces,
                IFirewallService fw,
                IDiagnosticRunner runner,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            if (!v.TryHost(req.Target, out var host, out var err)) return Bad<PingResult>(err);
            if (!v.TryFwmark(req.Fwmark, out var mark, out err)) return Bad<PingResult>(err);
            string? iface = null;
            if (!string.IsNullOrWhiteSpace(req.Interface) &&
                !v.TryInterfaceName(req.Interface, await AllowedInterfacesAsync(fw, ifaces, ct), out iface, out err))
                return Bad<PingResult>(err);
            var count = v.Clamp(req.Count, 1, 10);
            var timeout = v.Clamp(req.TimeoutSec, 1, 10);

            var ip = await ping.ResolveAsync(host, ct);
            if (ip is null) return Bad<PingResult>($"Could not resolve '{host}'.");

            var clean = new PingRequest(host, iface, mark > 0 ? $"0x{mark:x}" : null, count, timeout);
            var env = await runner.RunAsync(DiagTools.Ping, DiagFamilies.Ping, host, user.Identity?.Name, clean,
                TimeSpan.FromSeconds(count * (timeout + 1) + 5),
                async token =>
                {
                    var r = await ping.PingAsync(ip, iface, mark, count, timeout, token);
                    var status = r.Error is not null ? DiagRunStatus.Error
                        : r.Sent > 0 && r.Received == r.Sent ? DiagRunStatus.Ok
                        : r.Received > 0 ? DiagRunStatus.Warn
                        : DiagRunStatus.Fail;
                    var summary = r.Error ?? $"{r.Received}/{r.Sent} replies from {ip} via {r.Via}"
                        + (r.RttAvgMs is { } avg ? $", avg {avg:0.#} ms" : string.Empty);
                    return new DiagOutcome<PingResult>(r, status, summary);
                }, ct);

            await AuditAsync(audit, DiagTools.Ping, host, env, user, ctx, ct);
            return Respond(env);
        });

        // ───────────────────────── traceroute ─────────────────────────
        grp.MapPost("/traceroute", async (
                TracerouteRequest req,
                IDiagnosticInputValidator v,
                IPingProbeService ping,
                IInterfaceHealthService ifaces,
                IFirewallService fw,
                IDiagnosticRunner runner,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            if (!v.TryHost(req.Target, out var host, out var err)) return Bad<TracerouteResult>(err);
            if (!v.TryFwmark(req.Fwmark, out var mark, out err)) return Bad<TracerouteResult>(err);
            string? iface = null;
            if (!string.IsNullOrWhiteSpace(req.Interface) &&
                !v.TryInterfaceName(req.Interface, await AllowedInterfacesAsync(fw, ifaces, ct), out iface, out err))
                return Bad<TracerouteResult>(err);
            var hops = v.Clamp(req.MaxHops, 1, 30);
            var timeout = v.Clamp(req.TimeoutSec, 1, 5);

            var ip = await ping.ResolveAsync(host, ct);
            if (ip is null) return Bad<TracerouteResult>($"Could not resolve '{host}'.");

            var clean = new TracerouteRequest(host, iface, mark > 0 ? $"0x{mark:x}" : null, hops, timeout);
            // Marked traces spawn one ping per hop; keep the whole thing under the client's 30 s.
            var budget = TimeSpan.FromSeconds(Math.Min(25, hops * (timeout + 1) + 3));
            var env = await runner.RunAsync(DiagTools.Traceroute, DiagFamilies.Ping, host, user.Identity?.Name, clean, budget,
                async token =>
                {
                    var r = await ping.TracerouteAsync(ip, iface, mark, hops, timeout, token);
                    var status = r.Error is not null ? DiagRunStatus.Error : r.Reached ? DiagRunStatus.Ok : DiagRunStatus.Warn;
                    var summary = r.Error ?? (r.Reached
                        ? $"Reached {ip} in {r.Hops.Count} hop(s) via {r.Via}"
                        : $"Did not reach {ip} within {r.Hops.Count} hop(s) via {r.Via}");
                    return new DiagOutcome<TracerouteResult>(r, status, summary);
                }, ct);

            await AuditAsync(audit, DiagTools.Traceroute, host, env, user, ctx, ct);
            return Respond(env);
        });

        // ───────────────────────── route oracle ─────────────────────────
        grp.MapPost("/route-get", async (
                RouteGetRequest req,
                IDiagnosticInputValidator v,
                IPingProbeService resolver,
                IRouteOracleService routes,
                IInterfaceHealthService ifaces,
                IFirewallService fw,
                IDiagnosticRunner runner,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            if (!v.TryHost(req.Target, out var host, out var err)) return Bad<RouteGetResult>(err);
            if (!v.TryFwmark(req.Fwmark, out var mark, out err)) return Bad<RouteGetResult>(err);
            string? from = null;
            if (!string.IsNullOrWhiteSpace(req.From))
            {
                if (!v.TryCidrOrIp(req.From, out from, out err) || from.Contains('/')) return Bad<RouteGetResult>(err ?? "From must be a single IP address.");
            }
            string? iif = null;
            if (!string.IsNullOrWhiteSpace(req.Iif) &&
                !v.TryInterfaceName(req.Iif, await AllowedInterfacesAsync(fw, ifaces, ct), out iif, out err))
                return Bad<RouteGetResult>(err);
            if (iif is not null && from is null) return Bad<RouteGetResult>("iif requires a source address (from).");

            var ip = await resolver.ResolveAsync(host, ct);
            if (ip is null) return Bad<RouteGetResult>($"Could not resolve '{host}'.");

            var clean = new RouteGetRequest(host, mark > 0 ? $"0x{mark:x}" : null, from, iif);
            var env = await runner.RunAsync(DiagTools.RouteGet, DiagFamilies.Route, host, user.Identity?.Name, clean, TimeSpan.FromSeconds(8),
                async token =>
                {
                    var r = await routes.GetAsync(ip, mark, from, iif, token);
                    var status = r.Error is not null ? DiagRunStatus.Error
                        : r.Dev is null ? DiagRunStatus.Fail
                        : r.Warnings.Count > 0 ? DiagRunStatus.Warn
                        : DiagRunStatus.Ok;
                    var summary = r.Error ?? (r.Dev is null
                        ? $"No route to {ip}"
                        : $"{ip} → dev {r.Dev}" + (r.Gateway is null ? string.Empty : $" via {r.Gateway}")
                                                + (r.Table is null ? string.Empty : $" (table {r.Table})")
                                                + (r.Src is null ? string.Empty : $", src {r.Src}"));
                    return new DiagOutcome<RouteGetResult>(r, status, summary);
                }, ct);

            await AuditAsync(audit, DiagTools.RouteGet, host, env, user, ctx, ct);
            return Respond(env);
        });

        // ───────────────────────── conntrack lookup ─────────────────────────
        grp.MapPost("/conntrack", async (
                ConntrackLookupRequest req,
                IDiagnosticInputValidator v,
                IConntrackLookupService conntrack,
                IDiagnosticRunner runner,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            string? src = null, dst = null;
            if (!string.IsNullOrWhiteSpace(req.Src) && !v.TryCidrOrIp(req.Src, out src, out var err)) return Bad<ConntrackLookupResult>(err);
            if (!string.IsNullOrWhiteSpace(req.Dst) && !v.TryCidrOrIp(req.Dst, out dst, out err)) return Bad<ConntrackLookupResult>(err);
            if (!v.TryProto(req.Proto, out var proto, out err)) return Bad<ConntrackLookupResult>(err);
            if (!v.TryPort(req.Port, out var port, out err)) return Bad<ConntrackLookupResult>(err);
            if (src is null && dst is null && string.IsNullOrEmpty(proto) && port == 0)
                return Bad<ConntrackLookupResult>("Give at least one filter (source, destination, protocol or port).");
            var limit = v.Clamp(req.Limit, 1, 500);

            var target = src ?? dst ?? (port > 0 ? $"{proto}/{port}" : proto);
            var clean = new ConntrackLookupRequest(src, dst, string.IsNullOrEmpty(proto) ? null : proto, port > 0 ? port : null, limit);
            var env = await runner.RunAsync(DiagTools.Conntrack, DiagFamilies.Conntrack, target, user.Identity?.Name, clean, TimeSpan.FromSeconds(12),
                async token =>
                {
                    var r = await conntrack.LookupAsync(src, dst, proto, port, limit, token);
                    var status = r.Error is not null ? DiagRunStatus.Error : r.Total == 0 ? DiagRunStatus.Warn : DiagRunStatus.Ok;
                    var summary = r.Error ?? (r.Total == 0 ? "No matching flows" : $"{r.Total} matching flow(s)" + (r.Truncated ? $", showing {r.Flows.Count}" : string.Empty));
                    return new DiagOutcome<ConntrackLookupResult>(r, status, summary);
                }, ct);

            await AuditAsync(audit, DiagTools.Conntrack, target, env, user, ctx, ct);
            return Respond(env);
        });

        // ───────────────────────── kernel drop log ─────────────────────────
        grp.MapPost("/drop-log", async (
                DropLogRequest req,
                IDiagnosticInputValidator v,
                IDropLogService drops,
                IInterfaceHealthService ifaces,
                IFirewallService fw,
                IOptions<DiagnosticsOptions> opts,
                IDiagnosticRunner runner,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            string? iface = null;
            if (!string.IsNullOrWhiteSpace(req.Interface) &&
                !v.TryInterfaceName(req.Interface, await AllowedInterfacesAsync(fw, ifaces, ct), out iface, out var err))
                return Bad<DropLogResult>(err);
            var filter = (req.Filter ?? "drops").Trim().ToLowerInvariant();
            if (!DropLogFilters.Contains(filter)) return Bad<DropLogResult>("Filter must be drops, martians, wg or all.");
            var since = v.Clamp(req.SinceMinutes, 5, 1440);
            var lines = v.Clamp(req.Lines, 50, opts.Value.MaxJournalLines);

            var clean = new DropLogRequest(iface, since, lines, filter);
            var env = await runner.RunAsync(DiagTools.DropLog, DiagFamilies.Journal, iface ?? filter, user.Identity?.Name, clean, TimeSpan.FromSeconds(15),
                async token =>
                {
                    var r = await drops.QueryAsync(iface, since, lines, filter, token);
                    var status = r.Error is not null ? DiagRunStatus.Error : DiagRunStatus.Ok;
                    var summary = r.Error ?? $"{r.Entries.Count} {filter} entr{(r.Entries.Count == 1 ? "y" : "ies")} in the last {since} min ({r.Scanned} lines scanned"
                        + (r.Truncated ? ", capped" : string.Empty) + ")";
                    return new DiagOutcome<DropLogResult>(r, status, summary);
                }, ct);

            await AuditAsync(audit, DiagTools.DropLog, iface ?? filter, env, user, ctx, ct);
            return Respond(env);
        });

        // ───────────────────────── VPN doctor ─────────────────────────
        grp.MapPost("/vpn/doctor", async (
                VpnDoctorRequest req,
                NetFirewall.Services.Diagnostics.Vpn.IVpnDoctorService doctor,
                IDiagnosticRunner runner,
                IOptions<DiagnosticsOptions> opts,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            var budget = TimeSpan.FromSeconds(Math.Clamp(opts.Value.DoctorBudgetSeconds, 10, 25));
            var env = await runner.RunAsync(DiagTools.VpnDoctor, DiagFamilies.Doctor, null, user.Identity?.Name, req, budget,
                async token =>
                {
                    var report = await doctor.RunAsync(req, token);
                    return new DiagOutcome<DiagReport>(report, report.RunStatus, $"{report.Subject}: {report.Summary}");
                }, ct);

            await AuditAsync(audit, DiagTools.VpnDoctor, env.Data?.Result?.Subject, env, user, ctx, ct);
            return Respond(env);
        });

        grp.MapPost("/vpn/probe", async (
                VpnProbeRequest req,
                IDiagnosticInputValidator v,
                NetFirewall.Services.Diagnostics.Vpn.IVpnDoctorService doctor,
                IDiagnosticRunner runner,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            string? target = null;
            if (!string.IsNullOrWhiteSpace(req.Target) && !v.TryHost(req.Target, out target, out var err))
                return Bad<VpnProbeResult>(err);
            var mode = (req.Mode ?? "both").Trim().ToLowerInvariant();
            if (mode is not ("mark" or "bind" or "both")) return Bad<VpnProbeResult>("Mode must be mark, bind or both.");

            var clean = new VpnProbeRequest(target, mode);
            var env = await runner.RunAsync(DiagTools.VpnProbe, DiagFamilies.Probe, target, user.Identity?.Name, clean, TimeSpan.FromSeconds(20),
                async token =>
                {
                    var r = await doctor.ProbeAsync(clean, token);
                    var status = r.Verdict switch
                    {
                        "ok" => DiagRunStatus.Ok,
                        "inconclusive" => DiagRunStatus.Warn,
                        _ => DiagRunStatus.Fail,
                    };
                    return new DiagOutcome<VpnProbeResult>(r, status, $"{r.Verdict}: {r.Explanation}");
                }, ct);

            await AuditAsync(audit, DiagTools.VpnProbe, target, env, user, ctx, ct);
            return Respond(env);
        });

        grp.MapPost("/vpn/compare", async (
                VpnCompareRequest req,
                IDiagnosticInputValidator v,
                NetFirewall.Services.Diagnostics.Vpn.IVpnDoctorService doctor,
                IDiagnosticRunner runner,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            var text = req.ConfigText ?? string.Empty;
            if (text.Length == 0) return Bad<VpnCompareResult>("Paste the wg-quick config you were issued.");
            if (text.Length > 16 * 1024) return Bad<VpnCompareResult>("Config is too large (16 KB max).");

            // Redact before the text can reach diag_runs.params.
            var redacted = v.RedactWgConfig(text);
            var env = await runner.RunAsync(DiagTools.VpnCompare, DiagFamilies.Doctor, null, user.Identity?.Name,
                new VpnCompareRequest(redacted), TimeSpan.FromSeconds(10),
                async token =>
                {
                    var r = await doctor.CompareIssuedConfigAsync(redacted, token);
                    var status = r.Overall switch
                    {
                        DiagCheckStatus.Fail => DiagRunStatus.Fail,
                        DiagCheckStatus.Warn => DiagRunStatus.Warn,
                        _ => DiagRunStatus.Ok,
                    };
                    var bad = r.Differences.Count(d => d.Severity is DiagCheckStatus.Fail or DiagCheckStatus.Warn);
                    return new DiagOutcome<VpnCompareResult>(r, status, bad == 0 ? "Issued config matches" : $"{bad} difference(s) from the issued config");
                }, ct);

            await AuditAsync(audit, DiagTools.VpnCompare, null, env, user, ctx, ct);
            return Respond(env);
        });

        // ───────────────────────── live panels (not persisted) ─────────────────────────
        grp.MapGet("/interfaces/health", async (IInterfaceHealthService ifaces, CancellationToken ct) =>
            Results.Json(ServiceResponse<IReadOnlyList<InterfaceHealth>>.Ok(await ifaces.GetAllAsync(ct), "OK")));

        grp.MapGet("/interfaces/{name}/health", async (string name, IDiagnosticInputValidator v, IInterfaceHealthService ifaces, IFirewallService fw, CancellationToken ct) =>
        {
            if (!v.TryInterfaceName(name, await AllowedInterfacesAsync(fw, ifaces, ct), out var iface, out var err))
                return Results.Json(ServiceResponse<InterfaceHealth>.Fail(err ?? "Invalid interface."), statusCode: 400);
            var h = await ifaces.GetAsync(iface, ct);
            return h is null
                ? Results.Json(ServiceResponse<InterfaceHealth>.Fail("Interface health is Linux-only."), statusCode: 200)
                : Results.Json(ServiceResponse<InterfaceHealth>.Ok(h, "OK"));
        });

        grp.MapGet("/neighbors", async (string? iface, IDiagnosticInputValidator v, IInterfaceHealthService ifaces, IFirewallService fw, CancellationToken ct) =>
        {
            string? dev = null;
            if (!string.IsNullOrWhiteSpace(iface) &&
                !v.TryInterfaceName(iface, await AllowedInterfacesAsync(fw, ifaces, ct), out dev, out var err))
                return Results.Json(ServiceResponse<IReadOnlyList<NeighborEntry>>.Fail(err ?? "Invalid interface."), statusCode: 400);
            return Results.Json(ServiceResponse<IReadOnlyList<NeighborEntry>>.Ok(await ifaces.NeighborsAsync(dev, ct), "OK"));
        });

        grp.MapGet("/sysctl", async (string? iface, IDiagnosticInputValidator v, ISysctlSanityService sysctl, IInterfaceHealthService ifaces, IFirewallService fw, CancellationToken ct) =>
        {
            string? dev = null;
            if (!string.IsNullOrWhiteSpace(iface) &&
                !v.TryInterfaceName(iface, await AllowedInterfacesAsync(fw, ifaces, ct), out dev, out var err))
                return Results.Json(ServiceResponse<IReadOnlyList<DiagCheck>>.Fail(err ?? "Invalid interface."), statusCode: 400);
            return Results.Json(ServiceResponse<IReadOnlyList<DiagCheck>>.Ok(await sysctl.EvaluateAsync(dev, ct), "OK"));
        });

        // ───────────────────────── WAN / DHCP / DNS doctors ─────────────────────────
        // Same shape as the VPN doctor: read-only, budgeted, persisted to diag_runs.
        grp.MapPost("/wan/doctor", async (
                IDoctorRunner _unused,
                NetFirewall.Services.Diagnostics.Doctors.IWanDoctorService doctor,
                IDiagnosticRunner runner, IOptions<DiagnosticsOptions> opts,
                IAuthAuditService audit, ClaimsPrincipal user, HttpContext ctx, CancellationToken ct) =>
            await RunDoctorAsync(DiagTools.WanDoctor, doctor.RunAsync, runner, opts, audit, user, ctx, ct));

        grp.MapPost("/dhcp/doctor", async (
                NetFirewall.Services.Diagnostics.Doctors.IDhcpDoctorService doctor,
                IDiagnosticRunner runner, IOptions<DiagnosticsOptions> opts,
                IAuthAuditService audit, ClaimsPrincipal user, HttpContext ctx, CancellationToken ct) =>
            await RunDoctorAsync(DiagTools.DhcpDoctor, doctor.RunAsync, runner, opts, audit, user, ctx, ct));

        grp.MapPost("/dns/doctor", async (
                NetFirewall.Services.Diagnostics.Doctors.IDnsDoctorService doctor,
                IDiagnosticRunner runner, IOptions<DiagnosticsOptions> opts,
                IAuthAuditService audit, ClaimsPrincipal user, HttpContext ctx, CancellationToken ct) =>
            await RunDoctorAsync(DiagTools.DnsDoctor, doctor.RunAsync, runner, opts, audit, user, ctx, ct));

        // ═════════════════════ phase 2: invasive tools ═════════════════════
        // Admin only, TOTP step-up, audited at start/stop/download. These either
        // mutate the kernel (a temporary nftables table) or write raw traffic to
        // disk, so they do not share the read-only group's relaxed gate.
        var inv = app.MapGroup("/v1/diagnostics")
            .RequireAuthorization(p => p.RequireRole(UserRoles.Admin));

        // ── flow inspector ──
        inv.MapPost("/trace/start", async (
                TraceRequest req,
                IDiagnosticInputValidator v,
                NetFirewall.Services.Diagnostics.Trace.IFlowInspectorService tracer,
                IInterfaceHealthService ifaces,
                IFirewallService fw,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            string? src = null, dst = null, iface = null;
            if (!string.IsNullOrWhiteSpace(req.Src) && !v.TryCidrOrIp(req.Src, out src, out var err)) return BadJob(err);
            if (!string.IsNullOrWhiteSpace(req.Dst) && !v.TryCidrOrIp(req.Dst, out dst, out err)) return BadJob(err);
            if (!v.TryProto(req.Protocol, out var proto, out err)) return BadJob(err);
            if (!v.TryPort(req.Port, out var port, out err)) return BadJob(err);
            if (!string.IsNullOrWhiteSpace(req.Interface) &&
                !v.TryInterfaceName(req.Interface, await AllowedInterfacesAsync(fw, ifaces, ct), out iface, out err))
                return BadJob(err);

            // An unfiltered trace floods the kernel log and taxes every packet on a
            // live firewall — refuse it rather than let one click hurt throughput.
            if (src is null && dst is null && string.IsNullOrEmpty(proto) && iface is null)
                return BadJob("Give at least one matcher (source, destination, protocol or interface) — an unfiltered trace would mark every packet on the box.");

            var clean = new TraceRequest(src, dst, string.IsNullOrEmpty(proto) ? null : proto,
                port > 0 ? port : null, iface, v.Clamp(req.DurationSec, 5, 60), v.Clamp(req.MaxEvents, 10, 5000));

            var id = tracer.Start(clean, user.Identity?.Name);
            if (id is null) return Busy<Guid>("Another trace or capture is already running.");

            await AuditJobAsync(audit, AuthAuditEvents.DiagTraceStarted, user, ctx, new { runId = id, clean.Src, clean.Dst, clean.Protocol, clean.Port, clean.Interface, clean.DurationSec }, ct);
            return Results.Json(ServiceResponse<Guid>.Ok(id.Value, "Trace started."));
        })
        .WithMetadata(new DaemonAllowRootPeerAttribute(), new DaemonRequireElevatedAttribute());

        // ── packet capture ──
        inv.MapPost("/capture/start", async (
                CaptureRequest req,
                IDiagnosticInputValidator v,
                NetFirewall.Services.Diagnostics.Capture.IPacketCaptureService capture,
                IInterfaceHealthService ifaces,
                IFirewallService fw,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            if (!v.TryInterfaceName(req.Interface, await AllowedInterfacesAsync(fw, ifaces, ct), out var iface, out var err))
                return BadJob(err);
            if (!v.TryBpfFilter(req.Filter, out var filter, out err)) return BadJob(err);

            // Compile the filter before we open a capture socket: a bad filter should
            // be a form error, not a job that dies two seconds in.
            if (!string.IsNullOrEmpty(filter) && await capture.ValidateFilterAsync(filter, ct) is { } compileError)
                return BadJob($"Filter rejected by tcpdump: {compileError}");

            var clean = new CaptureRequest(iface, string.IsNullOrEmpty(filter) ? null : filter,
                v.Clamp(req.DurationSec, 5, 60), v.Clamp(req.MaxPackets, 10, 2000), v.Clamp(req.Snaplen, 64, 262144));

            var id = capture.Start(clean, user.Identity?.Name);
            if (id is null) return Busy<Guid>("Another trace or capture is already running.");

            await AuditJobAsync(audit, AuthAuditEvents.DiagCaptureStarted, user, ctx, new { runId = id, clean.Interface, clean.Filter, clean.DurationSec, clean.MaxPackets }, ct);
            return Results.Json(ServiceResponse<Guid>.Ok(id.Value, "Capture started."));
        })
        .WithMetadata(new DaemonAllowRootPeerAttribute(), new DaemonRequireElevatedAttribute());

        // ── job status / cancel / download ──
        inv.MapGet("/jobs/{id:guid}", (Guid id, IDiagnosticJobRegistry jobs) =>
        {
            var job = jobs.Get(id);
            return job is null
                ? Results.Json(ServiceResponse<DiagJobSnapshot>.Fail("Unknown or expired job."), statusCode: 404)
                : Results.Json(ServiceResponse<DiagJobSnapshot>.Ok(job, job.State.ToString()));
        });

        inv.MapGet("/jobs", (IDiagnosticJobRegistry jobs) =>
            Results.Json(ServiceResponse<IReadOnlyList<DiagJobSnapshot>>.Ok(jobs.Recent(10), "OK")));

        inv.MapPost("/jobs/{id:guid}/cancel", async (
                Guid id, IDiagnosticJobRegistry jobs, IAuthAuditService audit, ClaimsPrincipal user, HttpContext ctx, CancellationToken ct) =>
        {
            var job = jobs.Get(id);
            if (job is null)
                return Results.Json(ServiceResponse<object>.Fail("Unknown or expired job."), statusCode: 404);

            if (jobs.Cancel(id))
            {
                await AuditJobAsync(audit, AuthAuditEvents.DiagJobCancelled, user, ctx, new { runId = id }, ct);
                return Results.Json(ServiceResponse<object>.Ok(new { }, "Stopping — the partial result is kept."));
            }

            // It finished between the panel's last refresh and the click. Nothing went
            // wrong, so this is not a red toast — the caller re-reads the job anyway.
            return Results.Json(ServiceResponse<object>.Ok(new { },
                $"That job already finished ({job.State.ToString().ToLowerInvariant()})."));
        })
        .WithMetadata(new DaemonAllowRootPeerAttribute(), new DaemonRequireElevatedAttribute());

        inv.MapGet("/capture/{id:guid}/download", async (
                Guid id,
                IDiagnosticJobRegistry jobs,
                NetFirewall.Services.Diagnostics.Capture.ICaptureStore store,
                IAuthAuditService audit,
                ClaimsPrincipal user,
                HttpContext ctx,
                CancellationToken ct) =>
        {
            var stream = store.OpenRead(id);
            if (stream is null) return Results.NotFound();

            var name = jobs.Get(id)?.Capture?.FileName ?? $"netfirewall-{id:N}.pcap";
            await AuditJobAsync(audit, AuthAuditEvents.DiagCaptureDownloaded, user, ctx, new { runId = id, name }, ct);
            return Results.Stream(stream, "application/vnd.tcpdump.pcap", name);
        })
        .WithMetadata(new DaemonAllowRootPeerAttribute(), new DaemonRequireElevatedAttribute());

        inv.MapDelete("/capture/{id:guid}", (Guid id, NetFirewall.Services.Diagnostics.Capture.ICaptureStore store) =>
            Results.Json(store.Delete(id)
                ? ServiceResponse<object>.Ok(new { }, "Capture deleted.")
                : ServiceResponse<object>.Fail("Capture not found.")))
        .WithMetadata(new DaemonAllowRootPeerAttribute(), new DaemonRequireElevatedAttribute());
    }

    // ───────────────────────── helpers ─────────────────────────

    /// <summary>Every doctor is the same request: one gate slot, one budget, one diag_runs row.</summary>
    private static async Task<IResult> RunDoctorAsync(
        string tool,
        Func<CancellationToken, Task<DiagReport>> run,
        IDiagnosticRunner runner,
        IOptions<DiagnosticsOptions> opts,
        IAuthAuditService audit,
        ClaimsPrincipal user,
        HttpContext ctx,
        CancellationToken ct)
    {
        var budget = TimeSpan.FromSeconds(Math.Clamp(opts.Value.DoctorBudgetSeconds, 10, 25));
        var env = await runner.RunAsync(tool, DiagFamilies.Doctor, null, user.Identity?.Name, new { }, budget,
            async token =>
            {
                var report = await run(token);
                return new DiagOutcome<DiagReport>(report, report.RunStatus, $"{report.Subject}: {report.Summary}");
            }, ct);

        await AuditAsync(audit, tool, env.Data?.Result?.Subject, env, user, ctx, ct);
        return Respond(env);
    }


    /// <summary>Interfaces the operator may name: live kernel links ∪ configured fw_interfaces (a stopped wg0 is configured but not live).</summary>
    private static async Task<IReadOnlySet<string>> AllowedInterfacesAsync(IFirewallService fw, IInterfaceHealthService ifaces, CancellationToken ct)
    {
        var set = new HashSet<string>(await ifaces.ListNamesAsync(ct), StringComparer.Ordinal);
        foreach (var i in await fw.GetInterfacesAsync(ct))
            if (!string.IsNullOrWhiteSpace(i.Name)) set.Add(i.Name);
        return set;
    }

    private static IResult BadJob(string? error) =>
        Results.Json(ServiceResponse<Guid>.Fail(error ?? "Invalid request."), statusCode: 400);

    /// <summary>409: the single invasive slot is taken. The UI tells the operator who/what holds it.</summary>
    private static IResult Busy<T>(string message) =>
        Results.Json(ServiceResponse<T>.Fail(message), statusCode: 409);

    private static async Task AuditJobAsync(
        IAuthAuditService audit, string evt, ClaimsPrincipal user, HttpContext ctx, object detail, CancellationToken ct)
    {
        try
        {
            Guid? uid = Guid.TryParse(user.FindFirstValue(ClaimTypes.NameIdentifier), out var g) ? g : null;
            await audit.LogAsync(evt, userId: uid, username: user.Identity?.Name,
                ip: ctx.Connection.RemoteIpAddress, userAgent: ctx.Request.Headers.UserAgent.ToString(),
                detail: detail, ct: ct);
        }
        catch
        {
            // Never fail an invasive action because the audit write hiccuped; the
            // action itself is already logged by the job registry.
        }
    }

    private static IResult Bad<T>(string? error) =>
        Results.Json(ServiceResponse<DiagRunEnvelope<T>>.Fail(error ?? "Invalid request."), statusCode: 400);

    /// <summary>200 for any completed run (its verdict is in Status), 409 when the gate refused, 500 when the tool itself broke.</summary>
    private static IResult Respond<T>(ServiceResponse<DiagRunEnvelope<T>> env) =>
        Results.Json(env, statusCode: env.Data?.Status == DiagRunStatus.Busy ? 409 : env.Success ? 200 : 500);

    private static async Task AuditAsync<T>(
        IAuthAuditService audit, string tool, string? target, ServiceResponse<DiagRunEnvelope<T>> env,
        ClaimsPrincipal user, HttpContext ctx, CancellationToken ct)
    {
        try
        {
            Guid? uid = Guid.TryParse(user.FindFirstValue(ClaimTypes.NameIdentifier), out var g) ? g : null;
            var denied = env.Data?.Status == DiagRunStatus.Busy;
            await audit.LogAsync(
                denied ? AuthAuditEvents.DiagDenied : AuthAuditEvents.DiagRun,
                userId: uid,
                username: user.Identity?.Name,
                ip: ctx.Connection.RemoteIpAddress,
                userAgent: ctx.Request.Headers.UserAgent.ToString(),
                detail: new { tool, target, runId = env.Data?.RunId, status = env.Data?.Status, durationMs = env.Data?.DurationMs },
                ct: ct);
        }
        catch
        {
            // Audit is best-effort for read-only tools; the run itself already succeeded or failed on its own terms.
        }
    }
}
