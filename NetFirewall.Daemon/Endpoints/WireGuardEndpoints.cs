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

        grp.MapPost("/apply", async (
                IWireGuardService data,
                IWireGuardApplyService apply,
                NetFirewall.Services.Firewall.IApplyHistoryService history,
                System.Security.Claims.ClaimsPrincipal user,
                CancellationToken ct) =>
        {
            var server = await data.GetServerAsync(ct);
            if (server is null)
                return Results.Json(ServiceResponse<FirewallEndpoints.NftApplyDto>.Fail("No WireGuard server configured."), statusCode: 400);

            var peers = await data.GetPeersAsync(server.Id, ct);
            var result = await apply.ApplyAsync(server, peers, ct);

            var msg = result.Success
                ? $"WireGuard {server.Name} applied (exit {result.ExitCode})."
                : result.Error ?? "wg apply failed";
            await history.RecordAsync("wireguard", result.Success, result.ExitCode, msg, user.Identity?.Name, ct);

            var dto = new FirewallEndpoints.NftApplyDto(result.ExitCode, result.BackupPath, result.Output, result.Error);
            return result.Success
                ? Results.Json(ServiceResponse<FirewallEndpoints.NftApplyDto>.Ok(dto, msg))
                : Results.Json(ServiceResponse<FirewallEndpoints.NftApplyDto>.Fail(msg), statusCode: 500);
        })
        .WithMetadata(new DaemonRequireElevatedAttribute());

        grp.MapPost("/stop", async (
                IWireGuardService data,
                IWireGuardApplyService apply,
                CancellationToken ct) =>
        {
            var server = await data.GetServerAsync(ct);
            if (server is null)
                return Results.Json(ServiceResponse<FirewallEndpoints.NftApplyDto>.Fail("No WireGuard server configured."), statusCode: 400);

            var result = await apply.StopAsync(server.Name, ct);
            var dto = new FirewallEndpoints.NftApplyDto(result.ExitCode, null, result.Output, result.Error);
            return result.Success
                ? Results.Json(ServiceResponse<FirewallEndpoints.NftApplyDto>.Ok(dto, $"WireGuard {server.Name} stopped."))
                : Results.Json(ServiceResponse<FirewallEndpoints.NftApplyDto>.Fail(result.Error ?? "wg stop failed"), statusCode: 500);
        })
        .WithMetadata(new DaemonRequireElevatedAttribute());

        grp.MapGet("/status", async (
                IWireGuardService data,
                IWireGuardApplyService apply,
                CancellationToken ct) =>
        {
            var server = await data.GetServerAsync(ct);
            if (server is null)
                return Results.Json(ServiceResponse<IReadOnlyList<WgPeerLiveStatus>>.Ok(Array.Empty<WgPeerLiveStatus>(), "No server."));

            var status = await apply.GetStatusAsync(server.Name, ct);
            return Results.Json(ServiceResponse<IReadOnlyList<WgPeerLiveStatus>>.Ok(status, "Status fetched."));
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
        .WithMetadata(new DaemonRequireElevatedAttribute());
    }

    public sealed record KeyPairDto(string PrivateKey, string PublicKey);
    public sealed record PskDto(string PresharedKey);
}
