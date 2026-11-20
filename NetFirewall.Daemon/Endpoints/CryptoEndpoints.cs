using Microsoft.Extensions.Options;
using NetFirewall.Models;
using NetFirewall.Services.Auth;
using NetFirewall.Services.Daemon;

namespace NetFirewall.Daemon.Endpoints;

/// <summary>
/// Crypto-as-a-service endpoints. The master key for TOTP secrets lives
/// inside this process (loaded from <c>NETFIREWALL_MASTER_KEY</c>); the Web
/// never sees it. A Web-process compromise can no longer decrypt stored TOTP
/// secrets without also compromising the daemon — which runs under different
/// user/perm boundaries.
///
/// <para><b>No user session.</b> The Web calls these BEFORE a session exists: TOTP
/// enrollment and the TOTP step of the login both run mid-login on a pending ticket
/// (AuthController / AccountController), so requiring a session made every fresh
/// install unable to enroll or log in with <c>Daemon:UseForTotp=true</c> (found by the
/// Debian 13 end-to-end install). The gate is the caller instead: the socket is
/// <c>0660 root:netfirewall</c> and <see cref="Auth.PeerCredentialMiddleware"/> admits only
/// <c>Daemon:AcceptedPeerUids</c> (the Web's UID and root). A user session would not add
/// protection here: a compromised Web process can already read the sessions table.</para>
/// </summary>
public static class CryptoEndpoints
{
    /// <summary>True when PeerCredentialMiddleware actually filters callers (a peer allow-list is set).</summary>
    public static bool IsPeerGated(DaemonOptions opts) =>
        opts.ExpectedPeerUid is not null || opts.AcceptedPeerUids is { Length: > 0 };

    public static void MapCryptoEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/v1/crypto")
            .AllowAnonymous()   // peer-credential gated, see above
            .AddEndpointFilter(async (ctx, next) =>
            {
                // Without a peer allow-list (dev) PeerCredentialMiddleware lets every local
                // caller through; never serve the TOTP master key's cipher in that mode.
                var opts = ctx.HttpContext.RequestServices.GetRequiredService<IOptions<DaemonOptions>>().Value;
                return IsPeerGated(opts)
                    ? await next(ctx)
                    : Results.Json(ServiceResponse<CryptoResponse>.Fail("Crypto requires Daemon:AcceptedPeerUids."), statusCode: 403);
            });

        grp.MapPost("/encrypt", async (CryptoRequest req, ITotpSecretCipher cipher, CancellationToken ct) =>
        {
            if (string.IsNullOrEmpty(req.Data))
                return Results.Json(ServiceResponse<CryptoResponse>.Fail("Missing 'data' field."), statusCode: 400);
            try
            {
                var input = Convert.FromBase64String(req.Data);
                var output = await cipher.EncryptAsync(input, ct);
                return Results.Json(ServiceResponse<CryptoResponse>.Ok(new CryptoResponse(Convert.ToBase64String(output)), "Encrypted."));
            }
            catch (FormatException)
            {
                return Results.Json(ServiceResponse<CryptoResponse>.Fail("'data' must be valid base64."), statusCode: 400);
            }
        });

        grp.MapPost("/decrypt", async (CryptoRequest req, ITotpSecretCipher cipher, CancellationToken ct) =>
        {
            if (string.IsNullOrEmpty(req.Data))
                return Results.Json(ServiceResponse<CryptoResponse>.Fail("Missing 'data' field."), statusCode: 400);
            try
            {
                var input = Convert.FromBase64String(req.Data);
                var output = await cipher.DecryptAsync(input, ct);
                return Results.Json(ServiceResponse<CryptoResponse>.Ok(new CryptoResponse(Convert.ToBase64String(output)), "Decrypted."));
            }
            catch (FormatException)
            {
                return Results.Json(ServiceResponse<CryptoResponse>.Fail("'data' must be valid base64."), statusCode: 400);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                // Don't leak details — wrong key vs tampered ciphertext indistinguishable to attacker.
                return Results.Json(ServiceResponse<CryptoResponse>.Fail("Decryption failed."), statusCode: 400);
            }
        });
    }

    public sealed record CryptoRequest(string? Data);
    public sealed record CryptoResponse(string Data);
}
