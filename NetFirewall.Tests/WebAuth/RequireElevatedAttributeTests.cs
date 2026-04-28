using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Routing;
using NetFirewall.Models.Auth;
using NetFirewall.Web.Auth;
using NetFirewall.Web.Filters;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// Step-up authorization filter. The whole point is "no elevated claim → no
/// destructive action", so every miss in this filter is a security hole. Tests
/// pin all four observable outcomes:
///   1. Anonymous user → standard cookie challenge (redirect to /login).
///   2. Authenticated basic session → 401 + HX-Trigger:showElevationModal with
///      the original URL/method so the modal can replay after step-up.
///   3. Authenticated elevated session → pass-through (Result stays null).
///   4. AuthLevel claim missing entirely → treated as basic (defense in depth).
/// </summary>
public class RequireElevatedAttributeTests
{
    private static AuthorizationFilterContext MakeContext(ClaimsPrincipal user, string method = "POST", string path = "/firewall/apply", string query = "")
    {
        var ctx = new DefaultHttpContext { User = user };
        ctx.Request.Method = method;
        ctx.Request.Path = path;
        ctx.Request.QueryString = new QueryString(query);

        var actionContext = new ActionContext(
            ctx,
            new RouteData(),
            new ActionDescriptor());

        return new AuthorizationFilterContext(actionContext, new List<IFilterMetadata>());
    }

    private static ClaimsPrincipal Unauthenticated() => new(new ClaimsIdentity()); // no auth scheme = not authenticated
    private static ClaimsPrincipal AuthenticatedWithLevel(string? level)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
            new(ClaimTypes.Name, "alice")
        };
        if (level is not null)
            claims.Add(new Claim(SessionCookieAuthHandler.AuthLevelClaim, level));
        return new ClaimsPrincipal(new ClaimsIdentity(claims, "test")); // truthy auth scheme = authenticated
    }

    // ── Unauthenticated → standard cookie challenge ────────────────────

    [Fact]
    public async Task UnauthenticatedUser_ProducesChallengeResult_NoCustomHeader()
    {
        var ctx = MakeContext(Unauthenticated());
        await new RequireElevatedAttribute().OnAuthorizationAsync(ctx);

        // Cookie auth handler will then redirect to /login via HandleChallengeAsync.
        var challenge = Assert.IsType<ChallengeResult>(ctx.Result);
        Assert.Contains(SessionCookieAuthHandler.SchemeName, challenge.AuthenticationSchemes);
        // No custom HX-Trigger here — anonymous flow goes through the normal
        // login redirect, not the elevation modal.
        Assert.False(ctx.HttpContext.Response.Headers.ContainsKey("HX-Trigger"));
    }

    // ── Basic session → 401 + showElevationModal trigger ───────────────

    [Fact]
    public async Task BasicSession_ProducesUnauthorized_WithRetryInfo()
    {
        var ctx = MakeContext(AuthenticatedWithLevel(AuthLevels.Basic),
            method: "POST", path: "/firewall/apply", query: "?dry=1");

        await new RequireElevatedAttribute().OnAuthorizationAsync(ctx);

        var result = Assert.IsType<ObjectResult>(ctx.Result);
        Assert.Equal(StatusCodes.Status401Unauthorized, result.StatusCode);

        // Body shape: anonymous record { needsElevation, retry } — important so
        // the front end knows to expect 401 here means "show elevation modal",
        // not "session died, redirect to login".
        var body = result.Value!;
        var bodyJson = System.Text.Json.JsonSerializer.Serialize(body);
        Assert.Contains("needsElevation", bodyJson);
        Assert.Contains("/firewall/apply", bodyJson);
        Assert.Contains("dry=1", bodyJson);
        Assert.Contains("POST", bodyJson);
    }

    [Fact]
    public async Task BasicSession_EmitsHxTriggerWithShowElevationModal_AndRetryUrl()
    {
        var ctx = MakeContext(AuthenticatedWithLevel(AuthLevels.Basic),
            method: "DELETE", path: "/users/abc-123");

        await new RequireElevatedAttribute().OnAuthorizationAsync(ctx);

        var hxTrigger = ctx.HttpContext.Response.Headers["HX-Trigger"].ToString();
        Assert.Contains("showElevationModal", hxTrigger);
        Assert.Contains("/users/abc-123", hxTrigger);
        Assert.Contains("DELETE", hxTrigger); // method preserved so the modal can replay correctly
    }

    // ── Elevated session → pass-through ────────────────────────────────

    [Fact]
    public async Task ElevatedSession_PassesThrough_NoResult_NoHeaderChange()
    {
        var ctx = MakeContext(AuthenticatedWithLevel(AuthLevels.Elevated));

        await new RequireElevatedAttribute().OnAuthorizationAsync(ctx);

        // Filter does NOT set Result → pipeline continues to the action.
        Assert.Null(ctx.Result);
        Assert.False(ctx.HttpContext.Response.Headers.ContainsKey("HX-Trigger"));
    }

    [Theory]
    [InlineData("ELEVATED")]
    [InlineData("Elevated")]
    [InlineData("elevated")]
    public async Task ElevatedClaim_CaseInsensitive(string casing)
    {
        var ctx = MakeContext(AuthenticatedWithLevel(casing));
        await new RequireElevatedAttribute().OnAuthorizationAsync(ctx);
        Assert.Null(ctx.Result);
    }

    // ── Defense in depth: missing or unexpected claim values ───────────

    [Fact]
    public async Task MissingAuthLevelClaim_TreatedAsBasic_NotElevated()
    {
        // If a refactor accidentally drops the auth_level claim from the
        // session cookie handler, the safe default is "basic" (block the
        // sensitive action), not "elevated" (silent privilege escalation).
        var ctx = MakeContext(AuthenticatedWithLevel(level: null));

        await new RequireElevatedAttribute().OnAuthorizationAsync(ctx);

        var result = Assert.IsType<ObjectResult>(ctx.Result);
        Assert.Equal(StatusCodes.Status401Unauthorized, result.StatusCode);
    }

    [Theory]
    [InlineData("admin")]
    [InlineData("operator")]
    [InlineData("anything-else")]
    public async Task UnexpectedAuthLevelValue_TreatedAsBasic_BlocksAction(string level)
    {
        // Only the literal "elevated" passes. Confusing role-vs-level shouldn't
        // accidentally elevate; the test pins that contract.
        var ctx = MakeContext(AuthenticatedWithLevel(level));

        await new RequireElevatedAttribute().OnAuthorizationAsync(ctx);

        Assert.IsType<ObjectResult>(ctx.Result);
    }

    // ── Retry info preserves query string ──────────────────────────────

    [Fact]
    public async Task BasicSession_NoQueryString_RetryUrlIsJustPath()
    {
        var ctx = MakeContext(AuthenticatedWithLevel(AuthLevels.Basic),
            method: "POST", path: "/route", query: "");

        await new RequireElevatedAttribute().OnAuthorizationAsync(ctx);

        var hx = ctx.HttpContext.Response.Headers["HX-Trigger"].ToString();
        Assert.Contains("\"url\":\"/route\"", hx);
    }
}
