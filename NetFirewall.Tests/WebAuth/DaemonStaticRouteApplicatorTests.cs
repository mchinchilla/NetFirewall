using NetFirewall.Web.Daemon;
using Moq;
using NetFirewall.Models;
using NetFirewall.Models.System;
using NetFirewall.Services.Daemon;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// Thin proxy: every call hands off to <see cref="IDaemonClient"/>. Pinning
/// the routing so a refactor that adds local fallback (or worse, swallows
/// the daemon failure) is intentional.
/// </summary>
public class DaemonStaticRouteApplicatorTests
{
    private readonly Mock<IDaemonClient> _daemon = new();
    private DaemonStaticRouteApplicator Create() => new(_daemon.Object);

    [Fact]
    public async Task ApplyAsync_DelegatesToDaemonApplyRoute_AndReturnsItsEnvelope()
    {
        var routeId = Guid.NewGuid();
        var envelope = ServiceResponse<NetworkApplyResult>.Ok(
            new NetworkApplyResult { Success = true, Message = "applied" }, "ok");
        _daemon.Setup(d => d.ApplyRouteAsync(routeId, It.IsAny<CancellationToken>()))
               .ReturnsAsync(envelope);

        var result = await Create().ApplyAsync(routeId);

        Assert.Same(envelope, result);
        _daemon.Verify(d => d.ApplyRouteAsync(routeId, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task RemoveAsync_DelegatesToDaemonRemoveRoute_AndReturnsItsEnvelope()
    {
        var routeId = Guid.NewGuid();
        var envelope = ServiceResponse<NetworkApplyResult>.Ok(
            new NetworkApplyResult { Success = true }, "removed");
        _daemon.Setup(d => d.RemoveRouteAsync(routeId, It.IsAny<CancellationToken>()))
               .ReturnsAsync(envelope);

        var result = await Create().RemoveAsync(routeId);

        Assert.Same(envelope, result);
        _daemon.Verify(d => d.RemoveRouteAsync(routeId, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ApplyAsync_DaemonFailureEnvelope_PassesThroughUnaltered()
    {
        // The applicator must NOT translate / hide the daemon's "permission
        // denied" or "interface not found" — controllers surface those messages.
        var routeId = Guid.NewGuid();
        var failure = ServiceResponse<NetworkApplyResult>.Fail("daemon down");
        _daemon.Setup(d => d.ApplyRouteAsync(routeId, It.IsAny<CancellationToken>()))
               .ReturnsAsync(failure);

        var result = await Create().ApplyAsync(routeId);

        Assert.False(result.Success);
        Assert.Equal("daemon down", result.Message);
    }

    [Fact]
    public async Task ApplyAsync_PassesCancellationToken()
    {
        using var cts = new CancellationTokenSource();
        _daemon.Setup(d => d.ApplyRouteAsync(It.IsAny<Guid>(), cts.Token))
               .ReturnsAsync(ServiceResponse<NetworkApplyResult>.Ok(new NetworkApplyResult()));

        await Create().ApplyAsync(Guid.NewGuid(), cts.Token);

        _daemon.Verify(d => d.ApplyRouteAsync(It.IsAny<Guid>(), cts.Token), Times.Once);
    }
}
