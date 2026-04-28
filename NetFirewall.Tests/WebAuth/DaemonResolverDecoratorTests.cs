using NetFirewall.Web.Daemon;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Services.Daemon;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// Decorator that wraps the resolved <see cref="INetworkConfigService"/>
/// inside a <see cref="DaemonNetworkConfigService"/>. The contract callers
/// rely on:
///   - the decorator returns a writer with the SAME ConfigMethod as the inner
///     resolver picked (no override), so distro detection still works;
///   - apply/restart hop to the daemon (already covered indirectly here);
///   - the decorated writer is cached (one ResolveAsync per process) so we
///     don't pay the inner resolver's distro probe on every controller call.
/// </summary>
public class DaemonResolverDecoratorTests
{
    private readonly Mock<INetworkConfigResolver> _inner = new();
    private readonly Mock<IDaemonClient> _daemon = new();
    private readonly Mock<IFirewallService> _firewall = new();
    private readonly Mock<INetworkConfigService> _innerWriter = new();

    private DaemonResolverDecorator Create()
    {
        var services = new ServiceCollection();
        services.AddSingleton(_daemon.Object);
        services.AddSingleton(_firewall.Object);
        return new DaemonResolverDecorator(_inner.Object, services.BuildServiceProvider());
    }

    [Fact]
    public async Task ResolveAsync_WrapsInnerWriterInDaemonNetworkConfigService()
    {
        _inner.Setup(r => r.ResolveAsync(It.IsAny<CancellationToken>())).ReturnsAsync(_innerWriter.Object);

        var resolved = await Create().ResolveAsync();

        Assert.IsType<DaemonNetworkConfigService>(resolved);
    }

    [Fact]
    public async Task ResolveAsync_PreservesInnerConfigMethod()
    {
        // The decorator must NOT override the writer's ConfigMethod — distro
        // detection (Netplan / Interfaces / NetworkManager / Unknown) drives
        // file paths and shell commands; lying here causes the daemon to
        // write the wrong file.
        _inner.Setup(r => r.ResolveAsync(It.IsAny<CancellationToken>())).ReturnsAsync(_innerWriter.Object);
        _innerWriter.SetupGet(w => w.ConfigMethod)
                    .Returns(NetFirewall.Models.System.NetworkConfigMethod.NetworkManager);

        var resolved = await Create().ResolveAsync();

        Assert.Equal(NetFirewall.Models.System.NetworkConfigMethod.NetworkManager, resolved.ConfigMethod);
    }

    [Fact]
    public async Task ResolveAsync_CachesAfterFirstCall_InnerCalledOnce()
    {
        _inner.Setup(r => r.ResolveAsync(It.IsAny<CancellationToken>())).ReturnsAsync(_innerWriter.Object);
        var decorator = Create();

        var a = await decorator.ResolveAsync();
        var b = await decorator.ResolveAsync();
        var c = await decorator.ResolveAsync();

        Assert.Same(a, b);
        Assert.Same(a, c);
        // The inner resolver does distro detection (file IO) — must run at
        // most once per process. Running on every controller call would
        // re-read /etc/os-release on every request.
        _inner.Verify(r => r.ResolveAsync(It.IsAny<CancellationToken>()), Times.Once);
    }
}
