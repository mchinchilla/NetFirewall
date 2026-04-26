using System.Security.Cryptography;
using OtpNet;

namespace NetFirewall.Services.Auth;

public sealed class TotpService : ITotpService
{
    private const int SecretLengthBytes = 20;       // 160-bit, RFC 4226 §4 minimum recommended
    private const int Digits = 6;
    private const int StepSeconds = 30;
    private const int VerificationWindowSteps = 1;  // ±1 step (=30s) of clock skew

    public byte[] GenerateSecret() => RandomNumberGenerator.GetBytes(SecretLengthBytes);

    public string ToBase32(ReadOnlySpan<byte> secret) =>
        Base32Encoding.ToString(secret.ToArray()).TrimEnd('=');

    public Uri BuildEnrollmentUri(ReadOnlySpan<byte> secret, string issuer, string account)
    {
        var b32 = ToBase32(secret);
        var label = Uri.EscapeDataString($"{issuer}:{account}");
        var query = $"secret={b32}" +
                    $"&issuer={Uri.EscapeDataString(issuer)}" +
                    $"&algorithm=SHA1&digits={Digits}&period={StepSeconds}";
        return new Uri($"otpauth://totp/{label}?{query}");
    }

    public long? Verify(ReadOnlySpan<byte> secret, string code, long? lastUsedStep, DateTimeOffset now)
    {
        if (string.IsNullOrEmpty(code)) return null;

        // Strip whitespace some authenticators inject when copy-pasted.
        Span<char> trimmed = stackalloc char[code.Length];
        var len = 0;
        foreach (var c in code) if (!char.IsWhiteSpace(c)) trimmed[len++] = c;
        var normalized = new string(trimmed[..len]);
        if (normalized.Length != Digits) return null;

        var totp = new Totp(secret.ToArray(), step: StepSeconds, totpSize: Digits);
        if (!totp.VerifyTotp(now.UtcDateTime, normalized, out var matchedStep,
                              new VerificationWindow(VerificationWindowSteps, VerificationWindowSteps)))
            return null;

        // Replay protection — codes from already-accepted (or older) steps are rejected.
        var step = (long)matchedStep;
        if (lastUsedStep.HasValue && step <= lastUsedStep.Value) return null;
        return step;
    }
}
