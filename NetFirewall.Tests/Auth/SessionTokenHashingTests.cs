using NetFirewall.Services.Auth;
using Xunit;

namespace NetFirewall.Tests.Auth;

/// <summary>
/// Covers the deterministic helper <see cref="SessionService.HashToken"/>.
/// Full SessionService coverage (DB-backed lifecycle, sliding window, revocation)
/// requires Postgres and lives in the Phase 2 integration test suite.
/// </summary>
public class SessionTokenHashingTests
{
    [Fact]
    public void HashToken_IsDeterministic()
    {
        var a = SessionService.HashToken("the-cookie-value");
        var b = SessionService.HashToken("the-cookie-value");
        Assert.Equal(a, b);
    }

    [Fact]
    public void HashToken_ProducesUppercaseHex()
    {
        var hash = SessionService.HashToken("anything");
        Assert.Equal(64, hash.Length); // SHA-256 → 32 bytes → 64 hex chars
        Assert.Matches("^[0-9A-F]{64}$", hash);
    }

    [Fact]
    public void HashToken_DiffersForDifferentInputs()
    {
        Assert.NotEqual(
            SessionService.HashToken("token-a"),
            SessionService.HashToken("token-b"));
    }

    [Fact]
    public void HashToken_KnownVector()
    {
        // Sanity: SHA-256("hello") in uppercase hex.
        // Computed independently — pinning the algo so a future refactor
        // (e.g. switching to BLAKE3) is loud, not silent.
        const string expected = "2CF24DBA5FB0A30E26E83B2AC5B9E29E1B161E5C1FA7425E73043362938B9824";
        Assert.Equal(expected, SessionService.HashToken("hello"));
    }
}
