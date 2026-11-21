using System.Runtime.Versioning;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Daemon.Auth;
using NetFirewall.Models.Auth;
using Xunit;

namespace NetFirewall.Tests.Daemon;

/// <summary>
/// The daemon's endpoints are minimal APIs, which never run MVC filters — the
/// [DaemonRequire*] markers are only enforced by <see cref="DaemonEndpointGateMiddleware"/>.
/// These tests pin that enforcement: recovery is root-peer only, destructive endpoints need
/// an elevated Admin/Operator session (or the root-peer principal).
/// </summary>
// Pure logic; [SupportedOSPlatform] only silences CA1416 — the tests run everywhere.
[SupportedOSPlatform("linux")]
public class DaemonEndpointGateMiddlewareTests
{
    private sealed class FixedPeer(int? uid) : IPeerUidReader
    {
        public int? TryGetPeerUid(HttpContext context) => uid;
    }

    private static (HttpContext ctx, Func<bool> reached, DaemonEndpointGateMiddleware mw) Build(
        int? peerUid, ClaimsPrincipal? user, params object[] metadata)
    {
        var reached = false;
        var mw = new DaemonEndpointGateMiddleware(
            _ => { reached = true; return Task.CompletedTask; },
            new FixedPeer(peerUid),
            NullLogger<DaemonEndpointGateMiddleware>.Instance);

        var ctx = new DefaultHttpContext();
        ctx.Response.Body = new MemoryStream();
        ctx.SetEndpoint(new Endpoint(_ => Task.CompletedTask, new EndpointMetadataCollection(metadata), "test"));
        if (user is not null) ctx.User = user;
        return (ctx, () => reached, mw);
    }

    private static ClaimsPrincipal Session(string role, string level) => new(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.Name, "u"),
            new Claim(ClaimTypes.Role, role),
            new Claim(DaemonSessionAuthHandler.AuthLevelClaim, level),
        ], "DaemonSession", ClaimTypes.Name, ClaimTypes.Role));

    // The principal RootPeerBypassMiddleware installs for uid 0 without a session header.
    private static ClaimsPrincipal RootPeer() => new(new ClaimsIdentity(
        [
            new Claim(ClaimTypes.Name, "system-bootstrap"),
            new Claim(ClaimTypes.Role, "Admin"),
            new Claim(DaemonSessionAuthHandler.AuthLevelClaim, AuthLevels.Elevated),
        ], "RootPeer"));

    // ── root-peer gate (recovery endpoints) ─────────────────────────────

    [Theory]
    [InlineData(999)]   // the Web's UID — an accepted socket peer, but not root
    [InlineData(1000)]
    public async Task RootPeerGate_RefusesNonRootPeer(int uid)
    {
        var (ctx, reached, mw) = Build(uid, null, new DaemonRequireRootPeerAttribute());
        await mw.InvokeAsync(ctx);
        Assert.False(reached());
        Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task RootPeerGate_RefusesUnknownPeer()
    {
        var (ctx, reached, mw) = Build(null, null, new DaemonRequireRootPeerAttribute());
        await mw.InvokeAsync(ctx);
        Assert.False(reached());
        Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task RootPeerGate_AdmitsRoot()
    {
        var (ctx, reached, mw) = Build(0, null, new DaemonRequireRootPeerAttribute());
        await mw.InvokeAsync(ctx);
        Assert.True(reached());
    }

    // ── elevated gate (destructive endpoints) ───────────────────────────

    [Fact]
    public async Task ElevatedGate_RefusesAnonymous()
    {
        var (ctx, reached, mw) = Build(999, null, new DaemonRequireElevatedAttribute());
        await mw.InvokeAsync(ctx);
        Assert.False(reached());
        Assert.Equal(StatusCodes.Status401Unauthorized, ctx.Response.StatusCode);
    }

    [Theory]
    [InlineData(UserRoles.Admin)]
    [InlineData(UserRoles.Operator)]
    public async Task ElevatedGate_RefusesBasicSession(string role)
    {
        var (ctx, reached, mw) = Build(999, Session(role, AuthLevels.Basic), new DaemonRequireElevatedAttribute());
        await mw.InvokeAsync(ctx);
        Assert.False(reached());
        Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
    }

    [Fact]
    public async Task ElevatedGate_RefusesElevatedViewer()
    {
        var (ctx, reached, mw) = Build(999, Session(UserRoles.Viewer, AuthLevels.Elevated), new DaemonRequireElevatedAttribute());
        await mw.InvokeAsync(ctx);
        Assert.False(reached());
        Assert.Equal(StatusCodes.Status403Forbidden, ctx.Response.StatusCode);
    }

    [Theory]
    [InlineData(UserRoles.Admin)]
    [InlineData(UserRoles.Operator)]
    public async Task ElevatedGate_AdmitsElevatedAdminOrOperator(string role)
    {
        var (ctx, reached, mw) = Build(999, Session(role, AuthLevels.Elevated), new DaemonRequireElevatedAttribute());
        await mw.InvokeAsync(ctx);
        Assert.True(reached());
    }

    [Fact]
    public async Task ElevatedGate_AdmitsRootPeerPrincipal()
    {
        // Boot-time apply (netfirewall-bootstrap) has no session: it must keep working.
        var (ctx, reached, mw) = Build(0, RootPeer(), new DaemonRequireElevatedAttribute(), new DaemonAllowRootPeerAttribute());
        await mw.InvokeAsync(ctx);
        Assert.True(reached());
    }

    [Fact]
    public async Task UngatedEndpoint_PassesThrough()
    {
        var (ctx, reached, mw) = Build(999, null);
        await mw.InvokeAsync(ctx);
        Assert.True(reached());
    }
}
