using NetFirewall.Tui;
using NetFirewall.Tui.Screens;
using Xunit;

namespace NetFirewall.Tests.Tui;

/// <summary>
/// Pin the two pieces of TUI state that survive between screens — the opaque
/// daemon session token and the human-readable user identity. They live in
/// separate types on purpose: the screen rendering layer should NOT have a
/// reference to the bare token (don't tempt a future contributor into
/// logging it). Tests cover the threading contract on the token store and
/// the basic transitions on the identity state.
/// </summary>
public class TuiSessionStateTests
{
    // ── TuiSessionTokenProvider ────────────────────────────────────────

    [Fact]
    public void TokenProvider_FreshInstance_ReturnsNull()
    {
        var p = new TuiSessionTokenProvider();
        Assert.Null(p.GetCurrentToken());
    }

    [Fact]
    public void TokenProvider_SetThenGet_RoundTrips()
    {
        var p = new TuiSessionTokenProvider();
        p.SetToken("abc-123");
        Assert.Equal("abc-123", p.GetCurrentToken());
    }

    [Fact]
    public void TokenProvider_SetNull_ClearsToken()
    {
        // Logout path: SetToken(null) wipes the credential. A regression that
        // kept the token around would mean "logout" silently leaves auth headers
        // on subsequent calls — exactly the bug the recovery-screen needs to avoid.
        var p = new TuiSessionTokenProvider();
        p.SetToken("xyz");
        p.SetToken(null);
        Assert.Null(p.GetCurrentToken());
    }

    [Fact]
    public async Task TokenProvider_ConcurrentReadsAndWrites_DoNotThrow()
    {
        // Provider is shared across screens; the only consumer that mutates is
        // LoginScreen (login) and MainMenu (logout). They're sequential in the
        // current single-threaded UI loop, but background daemon-status probes
        // read concurrently. Pin that the lock holds.
        var p = new TuiSessionTokenProvider();
        var stop = DateTime.UtcNow.AddMilliseconds(200);
        var writers = Enumerable.Range(0, 4).Select(i => Task.Run(() =>
        {
            while (DateTime.UtcNow < stop) p.SetToken($"t-{i}-{Environment.TickCount}");
        })).ToArray();
        var readers = Enumerable.Range(0, 4).Select(_ => Task.Run(() =>
        {
            while (DateTime.UtcNow < stop) { var _ = p.GetCurrentToken(); }
        })).ToArray();
        await Task.WhenAll(writers.Concat(readers));
        // Pass condition: no race exception. The final value is deliberately not asserted.
    }

    // ── UserSessionState ───────────────────────────────────────────────

    [Fact]
    public void UserSessionState_FreshInstance_NotLoggedIn()
    {
        var s = new UserSessionState();
        Assert.False(s.IsLoggedIn);
        Assert.Null(s.Username);
        Assert.Null(s.DisplayName);
        Assert.Null(s.ExpiresAt);
    }

    [Fact]
    public void UserSessionState_Set_PopulatesAndFlipsLoggedIn()
    {
        var s = new UserSessionState();
        var when = DateTimeOffset.UtcNow.AddHours(8);
        s.Set("alice", "Alice Admin", when);

        Assert.True(s.IsLoggedIn);
        Assert.Equal("alice", s.Username);
        Assert.Equal("Alice Admin", s.DisplayName);
        Assert.Equal(when, s.ExpiresAt);
    }

    [Fact]
    public void UserSessionState_Clear_RestoresLoggedOut()
    {
        // Symmetric to Set — IsLoggedIn must flip back to false and the
        // identity fields must wipe so the menu line stops showing the prior user.
        var s = new UserSessionState();
        s.Set("alice", "Alice", DateTimeOffset.UtcNow.AddHours(1));
        s.Clear();

        Assert.False(s.IsLoggedIn);
        Assert.Null(s.Username);
        Assert.Null(s.DisplayName);
        Assert.Null(s.ExpiresAt);
    }

    [Fact]
    public void UserSessionState_Set_WithNullDisplayName_StillLoggedIn()
    {
        // Some users have no display_name (only username). The login screen
        // falls back to username for rendering — pin that IsLoggedIn is true
        // regardless of whether a display name was provided.
        var s = new UserSessionState();
        s.Set("bob", null, DateTimeOffset.UtcNow.AddHours(1));

        Assert.True(s.IsLoggedIn);
        Assert.Equal("bob", s.Username);
        Assert.Null(s.DisplayName);
    }
}
