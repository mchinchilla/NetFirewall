using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace NetFirewall.Services.Auth;

/// <summary>
/// Argon2id with OWASP 2024 defaults (m=64MB, t=3, p=4, 32-byte salt + 32-byte tag).
/// Hash is stored in the canonical encoded form
/// <c>$argon2id$v=19$m=65536,t=3,p=4$&lt;b64salt&gt;$&lt;b64hash&gt;</c>
/// so verification is fully self-contained — DB only needs one TEXT column.
/// </summary>
public sealed class Argon2PasswordHasher : IPasswordHasher
{
    // Current parameters. Bump these to upgrade defaults; existing hashes are
    // verified against their embedded params and flagged needs-rehash.
    private const int CurrentMemoryKiB = 64 * 1024; // 64 MB
    private const int CurrentIterations = 3;
    private const int CurrentParallelism = 4;
    private const int SaltLength = 32;
    private const int HashLength = 32;
    private const int Argon2idVersion = 19;

    public async Task<string> HashAsync(string password, CancellationToken ct = default)
    {
        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var hash = await ComputeAsync(password, salt, CurrentMemoryKiB, CurrentIterations, CurrentParallelism, HashLength, ct);
        return Encode(CurrentMemoryKiB, CurrentIterations, CurrentParallelism, salt, hash);
    }

    public async Task<PasswordVerificationResult> VerifyAsync(string password, string encodedHash, CancellationToken ct = default)
    {
        if (!TryDecode(encodedHash, out var memKb, out var iter, out var par, out var salt, out var expected))
            return new PasswordVerificationResult(false, false);

        var actual = await ComputeAsync(password, salt, memKb, iter, par, expected.Length, ct);
        var matches = CryptographicOperations.FixedTimeEquals(actual, expected);

        var needsRehash = matches && (memKb != CurrentMemoryKiB || iter != CurrentIterations || par != CurrentParallelism);
        return new PasswordVerificationResult(matches, needsRehash);
    }

    private static async Task<byte[]> ComputeAsync(
        string password, byte[] salt, int memKb, int iter, int par, int hashLen, CancellationToken ct)
    {
        // Konscious is sync; offload to a worker thread so callers can await.
        return await Task.Run(() =>
        {
            using var argon2 = new Argon2id(Encoding.UTF8.GetBytes(password))
            {
                Salt = salt,
                MemorySize = memKb,
                Iterations = iter,
                DegreeOfParallelism = par
            };
            return argon2.GetBytes(hashLen);
        }, ct);
    }

    private static string Encode(int memKb, int iter, int par, byte[] salt, byte[] hash) =>
        $"$argon2id$v={Argon2idVersion}$m={memKb},t={iter},p={par}$" +
        $"{Convert.ToBase64String(salt).TrimEnd('=')}$" +
        $"{Convert.ToBase64String(hash).TrimEnd('=')}";

    private static bool TryDecode(
        string encoded,
        out int memKb, out int iter, out int par,
        out byte[] salt, out byte[] hash)
    {
        memKb = 0; iter = 0; par = 0; salt = Array.Empty<byte>(); hash = Array.Empty<byte>();
        if (string.IsNullOrEmpty(encoded)) return false;

        // $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
        var parts = encoded.Split('$', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 5 || parts[0] != "argon2id") return false;
        if (!parts[1].StartsWith("v=") || !int.TryParse(parts[1][2..], out var v) || v != Argon2idVersion) return false;

        foreach (var token in parts[2].Split(','))
        {
            var kv = token.Split('=');
            if (kv.Length != 2 || !int.TryParse(kv[1], out var n)) return false;
            switch (kv[0])
            {
                case "m": memKb = n; break;
                case "t": iter = n; break;
                case "p": par = n; break;
            }
        }
        if (memKb <= 0 || iter <= 0 || par <= 0) return false;

        try
        {
            salt = Convert.FromBase64String(PadBase64(parts[3]));
            hash = Convert.FromBase64String(PadBase64(parts[4]));
            return salt.Length > 0 && hash.Length > 0;
        }
        catch
        {
            return false;
        }
    }

    private static string PadBase64(string s) =>
        s + new string('=', (4 - s.Length % 4) % 4);
}
