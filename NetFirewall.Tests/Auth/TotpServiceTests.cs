using NetFirewall.Services.Auth;
using OtpNet;
using Xunit;

namespace NetFirewall.Tests.Auth;

public class TotpServiceTests
{
    private readonly TotpService _svc = new();

    private const int StepSeconds = 30;

    private static string GenerateCode(byte[] secret, DateTimeOffset at) =>
        new Totp(secret, step: StepSeconds, totpSize: 6).ComputeTotp(at.UtcDateTime);

    private static long StepFor(DateTimeOffset at) =>
        (long)Math.Floor(at.ToUnixTimeSeconds() / (double)StepSeconds);

    [Fact]
    public void GenerateSecret_ReturnsTwentyRandomBytes()
    {
        var a = _svc.GenerateSecret();
        var b = _svc.GenerateSecret();

        Assert.Equal(20, a.Length);
        Assert.Equal(20, b.Length);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void ToBase32_StripsPadding()
    {
        var secret = _svc.GenerateSecret();
        var b32 = _svc.ToBase32(secret);

        Assert.DoesNotContain('=', b32);
        // 20 raw bytes → 32 chars in base32 (no padding needed at this length anyway).
        Assert.Equal(32, b32.Length);
    }

    [Fact]
    public void BuildEnrollmentUri_ProducesStandardOtpAuthFormat()
    {
        var secret = _svc.GenerateSecret();
        var uri = _svc.BuildEnrollmentUri(secret, "NetFirewall", "alice@example.com");

        Assert.Equal("otpauth", uri.Scheme);
        Assert.Equal("totp", uri.Host);
        // Label is URL-encoded "issuer:account"
        Assert.Equal("/NetFirewall%3Aalice%40example.com", uri.AbsolutePath);
        var query = uri.Query;
        Assert.Contains("secret=" + _svc.ToBase32(secret), query);
        Assert.Contains("issuer=NetFirewall", query);
        Assert.Contains("algorithm=SHA1", query);
        Assert.Contains("digits=6", query);
        Assert.Contains("period=30", query);
    }

    [Fact]
    public void Verify_AcceptsCurrentCode_AndReturnsMatchingStep()
    {
        var secret = _svc.GenerateSecret();
        var now = DateTimeOffset.UtcNow;
        var code = GenerateCode(secret, now);

        var matchedStep = _svc.Verify(secret, code, lastUsedStep: null, now);

        Assert.NotNull(matchedStep);
        Assert.Equal(StepFor(now), matchedStep);
    }

    [Fact]
    public void Verify_AcceptsCodeFromOneStepInThePast_WithinSkewWindow()
    {
        var secret = _svc.GenerateSecret();
        var now = DateTimeOffset.UtcNow;
        var thirtySecondsAgo = now.AddSeconds(-StepSeconds);
        var code = GenerateCode(secret, thirtySecondsAgo);

        var matchedStep = _svc.Verify(secret, code, lastUsedStep: null, now);

        Assert.NotNull(matchedStep);
        Assert.Equal(StepFor(thirtySecondsAgo), matchedStep);
    }

    [Fact]
    public void Verify_AcceptsCodeFromOneStepInTheFuture_WithinSkewWindow()
    {
        var secret = _svc.GenerateSecret();
        var now = DateTimeOffset.UtcNow;
        var thirtySecondsAhead = now.AddSeconds(StepSeconds);
        var code = GenerateCode(secret, thirtySecondsAhead);

        var matchedStep = _svc.Verify(secret, code, lastUsedStep: null, now);

        Assert.NotNull(matchedStep);
        Assert.Equal(StepFor(thirtySecondsAhead), matchedStep);
    }

    [Fact]
    public void Verify_RejectsCodeOutsideSkewWindow()
    {
        var secret = _svc.GenerateSecret();
        var now = DateTimeOffset.UtcNow;
        var twoStepsAgo = now.AddSeconds(-2 * StepSeconds);
        var code = GenerateCode(secret, twoStepsAgo);

        var matchedStep = _svc.Verify(secret, code, lastUsedStep: null, now);

        Assert.Null(matchedStep);
    }

    [Theory]
    [InlineData("")]
    [InlineData("12345")]    // too short
    [InlineData("1234567")]  // too long
    [InlineData("abcdef")]   // non-numeric — Totp will reject during compute compare
    public void Verify_RejectsMalformedCode(string code)
    {
        var secret = _svc.GenerateSecret();
        Assert.Null(_svc.Verify(secret, code, lastUsedStep: null, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Verify_RejectsNullCode()
    {
        var secret = _svc.GenerateSecret();
        Assert.Null(_svc.Verify(secret, null!, lastUsedStep: null, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Verify_ToleratesWhitespaceInCode()
    {
        var secret = _svc.GenerateSecret();
        var now = DateTimeOffset.UtcNow;
        var raw = GenerateCode(secret, now);
        // Many authenticator apps display "123 456" — make sure copy-paste works.
        var withSpaces = raw[..3] + " " + raw[3..];

        var matchedStep = _svc.Verify(secret, withSpaces, lastUsedStep: null, now);

        Assert.NotNull(matchedStep);
        Assert.Equal(StepFor(now), matchedStep);
    }

    [Fact]
    public void Verify_RejectsReplayOfTheSameStep()
    {
        var secret = _svc.GenerateSecret();
        var now = DateTimeOffset.UtcNow;
        var code = GenerateCode(secret, now);

        var firstUse = _svc.Verify(secret, code, lastUsedStep: null, now);
        Assert.NotNull(firstUse);

        // Replaying the same code with lastUsedStep == that step must fail.
        var secondUse = _svc.Verify(secret, code, lastUsedStep: firstUse, now);
        Assert.Null(secondUse);
    }

    [Fact]
    public void Verify_RejectsCodeFromOlderStepWhenLastUsedIsNewer()
    {
        var secret = _svc.GenerateSecret();
        var now = DateTimeOffset.UtcNow;
        var oldCode = GenerateCode(secret, now.AddSeconds(-StepSeconds));
        var lastUsedStep = StepFor(now); // claim we already accepted a newer step

        var matched = _svc.Verify(secret, oldCode, lastUsedStep, now);

        Assert.Null(matched); // even though it'd be valid for skew, it's stale
    }

    [Fact]
    public void Verify_AcceptsNewerStepEvenWhenAnEarlierStepWasAlreadyUsed()
    {
        var secret = _svc.GenerateSecret();
        var earlier = DateTimeOffset.UtcNow.AddSeconds(-StepSeconds);
        var later = earlier.AddSeconds(StepSeconds * 2);
        var laterCode = GenerateCode(secret, later);

        var matched = _svc.Verify(secret, laterCode, lastUsedStep: StepFor(earlier), later);

        Assert.NotNull(matched);
        Assert.Equal(StepFor(later), matched);
    }
}
