using NetFirewall.Daemon.Auth;
using NetFirewall.Models;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Vpn;

namespace NetFirewall.Daemon.Endpoints;

/// <summary>
/// WireGuard control plane. Key generation + interface up/down + status
/// parsing all live here because they need <c>CAP_NET_ADMIN</c> (or at
/// least the wg/wg-quick binaries which the daemon ships against).
/// </summary>
public static class WireGuardEndpoints
{
    public static void MapWireGuardEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/v1/wireguard").RequireAuthorization();

        grp.MapPost("/genkey", async (IWireGuardApplyService wg, CancellationToken ct) =>
        {
            try
            {
                var (priv, pub) = await wg.GenerateKeyPairAsync(ct);
                return Results.Json(ServiceResponse<KeyPairDto>.Ok(new KeyPairDto(priv, pub), "Key pair generated."));
            }
            catch (Exception ex)
            {
                return Results.Json(ServiceResponse<KeyPairDto>.Fail(ex.Message), statusCode: 500);
            }
        });

        grp.MapPost("/genpsk", async (IWireGuardApplyService wg, CancellationToken ct) =>
        {
            try
            {
                var psk = await wg.GeneratePresharedKeyAsync(ct);
                return Results.Json(ServiceResponse<PskDto>.Ok(new PskDto(psk), "Preshared key generated."));
            }
            catch (Exception ex)
            {
                return Results.Json(ServiceResponse<PskDto>.Fail(ex.Message), statusCode: 500);
            }
        });

        // Apply = write {name}.conf + bring the link up (or hot-reload) + re-install the
        // tunnel's policy routes (the kernel purged every `dev {name}` route with the link).
        // ?name= applies ONE interface; without it every enabled interface is applied (boot-time
        // apply, "Apply VPN"). The name is only ever looked up in wg_servers — the string that
        // reaches wg-quick is the stored, validated one, never the query text.
        grp.MapPost("/apply", async (
                IWireGuardService data,
                IWireGuardBringUpService bringUp,
                NetFirewall.Services.Firewall.IApplyHistoryService history,
                System.Security.Claims.ClaimsPrincipal user,
                CancellationToken ct,
                string? name = null) =>
        {
            var targets = await TargetsAsync(data, name, ct);
            if (targets is null)
                return Results.Json(ServiceResponse<FirewallEndpoints.NftApplyDto>.Fail($"No WireGuard interface '{name}'."), statusCode: 404);
            if (targets.Count == 0)
                return Results.Json(ServiceResponse<FirewallEndpoints.NftApplyDto>.Ok(
                    new FirewallEndpoints.NftApplyDto(0, null, "", null), "No WireGuard interface configured — nothing to apply."));

            var messages = new List<string>();
            var outputs = new System.Text.StringBuilder();
            var exit = 0;
            string? error = null;
            var ok = true;
            foreach (var server in targets)
            {
                var peers = await data.GetPeersAsync(server.Id, ct);
                var result = await bringUp.ApplyAsync(server, peers, ct);
                var msg = result.Describe(server.Name);
                messages.Add(msg);
                outputs.AppendLine(result.CombinedOutput);
                if (!result.Success)
                {
                    ok = false;
                    exit = exit == 0 ? result.Apply.ExitCode : exit;
                    error ??= result.Apply.Error ?? result.Routing?.Error;
                }
            }

            var summary = string.Join(" · ", messages);
            await history.RecordAsync("wireguard", ok, exit, summary, user.Identity?.Name, ct);
            var dto = new FirewallEndpoints.NftApplyDto(exit, null, outputs.ToString(), error);
            return ok
                ? Results.Json(ServiceResponse<FirewallEndpoints.NftApplyDto>.Ok(dto, summary))
                : Results.Json(ServiceResponse<FirewallEndpoints.NftApplyDto>.Fail(summary), statusCode: 500);
        })
        .WithMetadata(new DaemonAllowRootPeerAttribute(), new DaemonRequireElevatedAttribute());

        // ?name= stops one interface; without it every configured interface is brought down.
        grp.MapPost("/stop", async (
                IWireGuardService data,
                IWireGuardApplyService apply,
                CancellationToken ct,
                string? name = null) =>
        {
            var targets = await TargetsAsync(data, name, ct, includeDisabled: true);
            if (targets is null)
                return Results.Json(ServiceResponse<FirewallEndpoints.NftApplyDto>.Fail($"No WireGuard interface '{name}'."), statusCode: 404);
            if (targets.Count == 0)
                return Results.Json(ServiceResponse<FirewallEndpoints.NftApplyDto>.Fail("No WireGuard interface configured."), statusCode: 400);

            var outputs = new System.Text.StringBuilder();
            foreach (var server in targets)
            {
                var result = await apply.StopAsync(server.Name, ct);
                outputs.AppendLine(result.Output);
                if (!result.Success)
                    return Results.Json(ServiceResponse<FirewallEndpoints.NftApplyDto>.Fail(result.Error ?? $"wg stop {server.Name} failed"), statusCode: 500);
            }
            var names = string.Join(", ", targets.Select(s => s.Name));
            return Results.Json(ServiceResponse<FirewallEndpoints.NftApplyDto>.Ok(
                new FirewallEndpoints.NftApplyDto(0, null, outputs.ToString(), null), $"WireGuard {names} stopped."));
        })
        .WithMetadata(new DaemonAllowRootPeerAttribute(), new DaemonRequireElevatedAttribute());

        // Live peer status. ?name= for one interface; without it the peers of every
        // interface (public keys are unique per interface; callers join by key + server).
        grp.MapGet("/status", async (
                IWireGuardService data,
                IWireGuardApplyService apply,
                CancellationToken ct,
                string? name = null) =>
        {
            var targets = await TargetsAsync(data, name, ct, includeDisabled: true);
            if (targets is null || targets.Count == 0)
                return Results.Json(ServiceResponse<IReadOnlyList<WgPeerLiveStatus>>.Ok(Array.Empty<WgPeerLiveStatus>(), "No interface."));

            var all = new List<WgPeerLiveStatus>();
            foreach (var server in targets)
                all.AddRange(await apply.GetStatusAsync(server.Name, ct));
            return Results.Json(ServiceResponse<IReadOnlyList<WgPeerLiveStatus>>.Ok(all, "Status fetched."));
        });

        // GET /v1/wireguard/import — list wg-quick .conf files visible on disk.
        // The Web shows these so the operator can pick which one to onboard.
        grp.MapGet("/import", async (IWireGuardImporter importer, CancellationToken ct) =>
        {
            var names = await importer.ListAvailableAsync(ct);
            return Results.Json(ServiceResponse<IReadOnlyList<string>>.Ok(names, $"Found {names.Count} config(s)."));
        });

        // POST /v1/wireguard/import/{name} — parse the named config and UPSERT
        // into wg_servers + wg_peers. Idempotent on re-run. Does NOT touch the
        // live interface (use /apply afterwards). Requires elevation: it
        // overwrites whatever the operator may have edited in the UI.
        grp.MapPost("/import/{name}", async (
                string name,
                IWireGuardImporter importer,
                CancellationToken ct) =>
        {
            try
            {
                var result = await importer.ImportAsync(name, ct);
                return Results.Json(ServiceResponse<WireGuardImportResult>.Ok(result,
                    $"Imported {name} ({result.Mode}, {result.Peers.Count} peer(s))."));
            }
            catch (FileNotFoundException ex)
            {
                return Results.Json(ServiceResponse<object>.Fail(ex.Message), statusCode: 404);
            }
            catch (Exception ex)
            {
                return Results.Json(ServiceResponse<object>.Fail($"Import failed: {ex.Message}"), statusCode: 500);
            }
        })
        .WithMetadata(new DaemonAllowRootPeerAttribute(), new DaemonRequireElevatedAttribute());

        // POST /v1/wireguard/outbound — a NEW outbound client interface (wgcN) from the config a
        // VPN provider / remote site issued. Validated here (no script hooks, exactly one peer),
        // key derived here; DB only — Apply brings it up. Elevated: it stores a private key.
        grp.MapPost("/outbound", async (
                NetFirewall.Services.Daemon.WgOutboundCreateRequest req,
                IWireGuardImporter importer,
                CancellationToken ct) =>
        {
            try
            {
                var r = await importer.CreateOutboundAsync(req.ConfigText, req.Label, ct);
                var peer = r.Peers[0];
                return Results.Json(ServiceResponse<NetFirewall.Services.Daemon.WgOutboundCreatedDto>.Ok(
                    new(r.Server.Id, r.Server.Name, peer.Role, peer.Name, peer.Endpoint),
                    $"Connection {r.Server.Name} created ({peer.Name}). Apply VPN to bring it up."));
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException)
            {
                return Results.Json(ServiceResponse<NetFirewall.Services.Daemon.WgOutboundCreatedDto>.Fail(ex.Message), statusCode: 400);
            }
        })
        .WithMetadata(new DaemonAllowRootPeerAttribute(), new DaemonRequireElevatedAttribute());
    }

    /// <summary>
    /// The interfaces an endpoint acts on: the named one (null when it doesn't exist), else all
    /// (enabled only unless <paramref name="includeDisabled"/>).
    /// </summary>
    private static async Task<IReadOnlyList<WgServer>?> TargetsAsync(
        IWireGuardService data, string? name, CancellationToken ct, bool includeDisabled = false)
    {
        if (!string.IsNullOrWhiteSpace(name))
        {
            if (!WgInterfaceName.IsValid(name)) return null;
            var one = await data.GetServerByNameAsync(name, ct);
            return one is null ? null : [one];
        }
        var all = await data.ListServersAsync(ct);
        return includeDisabled ? all : all.Where(s => s.Enabled).ToList();
    }

    public sealed record KeyPairDto(string PrivateKey, string PublicKey);
    public sealed record PskDto(string PresharedKey);
}
