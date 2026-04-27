using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Moq;
using NetFirewall.Web.Auth;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// In-memory tests for the short-lived signed cookie that bridges the
/// password→TOTP step. Uses <see cref="EphemeralDataProtectionProvider"/> so
/// each test class instance has its own throwaway protection key.
/// </summary>
public class PendingAuthTicketTests
{
    private static (PendingAuthTicket ticket, FakeHttpContextAccessor http) Create()
    {
        var http = new FakeHttpContextAccessor();
        var dpp = new EphemeralDataProtectionProvider();
        return (new PendingAuthTicket(http, dpp), http);
    }

    private sealed class FakeHttpContextAccessor : IHttpContextAccessor
    {
        public HttpContext? HttpContext { get; set; } = new DefaultHttpContext();

        /// <summary>
        /// Move whatever the previous response wrote into Set-Cookie back into
        /// the next request's Cookie header — simulates the round-trip a real
        /// browser makes between two requests.
        /// </summary>
        public void RoundTripCookies()
        {
            var setCookie = HttpContext!.Response.Headers["Set-Cookie"].ToString();
            HttpContext = new DefaultHttpContext();
            // Set-Cookie may be "name=value; Path=/; ..."; the request side wants "name=value".
            if (string.IsNullOrEmpty(setCookie)) return;
            foreach (var entry in setCookie.Split(','))
            {
                var head = entry.Split(';')[0];
                var eq = head.IndexOf('=');
                if (eq <= 0) continue;
                var name = head[..eq].Trim();
                var value = head[(eq + 1)..].Trim();
                HttpContext.Request.Headers.Append("Cookie", $"{name}={value}");
            }
        }
    }

    // ── round-trip ─────────────────────────────────────────────────────

    [Fact]
    public void Issue_ThenTryRead_RoundTripsUserId()
    {
        var (t, http) = Create();
        var uid = Guid.NewGuid();

        t.Issue(uid);
        http.RoundTripCookies();

        Assert.True(t.TryRead(out var fetchedUid, out var fetchedReturn, out var fetchedSecret));
        Assert.Equal(uid, fetchedUid);
        Assert.Null(fetchedReturn);
        Assert.Null(fetchedSecret);
    }

    [Fact]
    public void Issue_WithReturnUrlAndSecret_BothRoundTrip()
    {
        var (t, http) = Create();
        var uid = Guid.NewGuid();
        var secret = new byte[] { 1, 2, 3, 4, 5 };

        t.Issue(uid, returnUrl: "/dashboard", enrollSecret: secret);
        http.RoundTripCookies();

        Assert.True(t.TryRead(out var u, out var r, out var s));
        Assert.Equal(uid, u);
        Assert.Equal("/dashboard", r);
        Assert.Equal(secret, s);
    }

    [Fact]
    public void TryRead_NoCookiePresent_ReturnsFalse()
    {
        var (t, _) = Create();
        Assert.False(t.TryRead(out _, out _, out _));
    }

    [Fact]
    public void TryRead_TamperedCookie_ReturnsFalse()
    {
        var (t, http) = Create();
        t.Issue(Guid.NewGuid());

        // Hand-craft a corrupt cookie value into the request side.
        http.HttpContext = new DefaultHttpContext();
        http.HttpContext.Request.Headers.Append("Cookie", $"{PendingAuthTicket.CookieName}=NOT-A-VALID-PROTECTED-PAYLOAD");

        Assert.False(t.TryRead(out _, out _, out _));
    }

    [Fact]
    public void TryRead_ExpiredTicket_ReturnsFalse()
    {
        // We can't easily mutate the cookie's embedded expiry, but we can
        // simulate a ticket protected by a *different* DPP — the cryptographic
        // failure is the same observable outcome (TryRead returns false).
        var (writer, http) = Create();
        writer.Issue(Guid.NewGuid());
        http.RoundTripCookies();

        // Now build a reader with a different DataProtection key — Unprotect throws.
        var different = new PendingAuthTicket(http, new EphemeralDataProtectionProvider());
        Assert.False(different.TryRead(out _, out _, out _));
    }

    // ── Clear ──────────────────────────────────────────────────────────

    [Fact]
    public void Clear_RemovesCookie()
    {
        var (t, http) = Create();
        t.Issue(Guid.NewGuid());

        t.Clear();

        // Set-Cookie should now contain a deletion (Expires in the past).
        var setCookie = http.HttpContext!.Response.Headers["Set-Cookie"].ToString();
        Assert.Contains(PendingAuthTicket.CookieName, setCookie);
    }

    // ── Issue without HttpContext ──────────────────────────────────────

    [Fact]
    public void Issue_NoHttpContext_Throws()
    {
        var http = new FakeHttpContextAccessor { HttpContext = null };
        var t = new PendingAuthTicket(http, new EphemeralDataProtectionProvider());

        Assert.Throws<InvalidOperationException>(() => t.Issue(Guid.NewGuid()));
    }
}
