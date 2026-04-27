using NetFirewall.Models;
using NetFirewall.Services.Auth;

namespace NetFirewall.Daemon.Endpoints;

/// <summary>
/// Crypto-as-a-service endpoints. The master key for TOTP secrets lives
/// inside this process (loaded from <c>NETFIREWALL_MASTER_KEY</c>); the Web
/// never sees it. A Web-process compromise can no longer decrypt stored TOTP
/// secrets without also compromising the daemon — which runs under different
/// user/perm boundaries.
///
/// Both endpoints require a valid Web session (same auth scheme as every
/// other /v1 endpoint). They do NOT require elevation: TOTP enrollment
/// already lives behind the elevation flow on the Web side.
/// </summary>
public static class CryptoEndpoints
{
    public static void MapCryptoEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/v1/crypto").RequireAuthorization();

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
