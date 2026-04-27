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
                CancellationToken ct) =>
        {
            var server = await data.GetServerAsync(ct);
            if (server is null)
                return Results.Json(ServiceResponse<FirewallEndpoints.NftApplyDto>.Fail("No WireGuard server configured."), statusCode: 400);

            var peers = await data.GetPeersAsync(server.Id, ct);
            var result = await apply.ApplyAsync(server, peers, ct);

            var dto = new FirewallEndpoints.NftApplyDto(result.ExitCode, result.BackupPath, result.Output, result.Error);
            return result.Success
                ? Results.Json(ServiceResponse<FirewallEndpoints.NftApplyDto>.Ok(dto, $"WireGuard {server.Name} applied (exit {result.ExitCode})."))
                : Results.Json(ServiceResponse<FirewallEndpoints.NftApplyDto>.Fail(result.Error ?? "wg apply failed"), statusCode: 500);
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
    }

    public sealed record KeyPairDto(string PrivateKey, string PublicKey);
    public sealed record PskDto(string PresharedKey);
}
