using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.System;
using NetFirewall.Services.Network;
using Xunit;

namespace NetFirewall.Tests.Network;

/// <summary>
/// Resolver picks the right <see cref="INetworkConfigService"/> implementation by
/// looking up the keyed-DI registration for the detected distro's
/// <see cref="NetworkConfigMethod"/>. Tests cover happy path, fallback, and the
/// caching behavior the daemon relies on (one detector hit per process).
/// </summary>
public class NetworkConfigResolverTests
{
    /// <summary>Lightweight stand-in that just remembers its method tag.</summary>
    private sealed class StubWriter : INetworkConfigService
    {
        public NetworkConfigMethod ConfigMethod { get; }
        public StubWriter(NetworkConfigMethod m) { ConfigMethod = m; }

        public Task<string> GenerateConfigAsync(NetFirewall.Models.Firewall.FwInterface iface,
            IEnumerable<NetFirewall.Models.Firewall.FwStaticRoute>? routes = null) =>
            Task.FromResult("");
        public Task<NetworkApplyResult> ApplyConfigAsync(NetFirewall.Models.Firewall.FwInterface iface,
            IEnumerable<NetFirewall.Models.Firewall.FwStaticRoute>? routes = null) =>
            Task.FromResult(new NetworkApplyResult());
        public Task<NetworkApplyResult> RestartNetworkingAsync() => Task.FromResult(new NetworkApplyResult());
        public Task<bool> ValidateConfigAsync(string config) => Task.FromResult(true);
        public string GetConfigFilePath(NetFirewall.Models.Firewall.FwInterface iface) => "";
        public Task<string?> DetectAddressingModeAsync(string interfaceName, CancellationToken ct = default) => Task.FromResult<string?>(null);
    }

    private static Mock<ILinuxDistroService> DistroReturning(NetworkConfigMethod method)
    {
        var m = new Mock<ILinuxDistroService>();
        m.Setup(s => s.DetectDistributionAsync(It.IsAny<CancellationToken>()))
         .ReturnsAsync(new LinuxDistroInfo { ConfigMethod = method });
        return m;
    }

    /// <summary>
    /// Builds a real DI container with one writer per registered method. The
    /// resolver speaks <c>GetKeyedService&lt;INetworkConfigService&gt;(method)</c>
    /// — there's no clean way to mock that surface, so we use the real container.
    /// </summary>
    private static IServiceProvider BuildProvider(params NetworkConfigMethod[] registered)
    {
        var services = new ServiceCollection();
        foreach (var m in registered)
            services.AddKeyedSingleton<INetworkConfigService>(m, new StubWriter(m));
        return services.BuildServiceProvider();
    }

    // ── happy path: writer present for the detected method ────────────

    [Theory]
    [InlineData(NetworkConfigMethod.Netplan)]
    [InlineData(NetworkConfigMethod.Interfaces)]
    [InlineData(NetworkConfigMethod.NetworkManager)]
    public async Task ResolveAsync_PicksWriterMatchingDetectedMethod(NetworkConfigMethod method)
    {
        var distro = DistroReturning(method);
        var provider = BuildProvider(NetworkConfigMethod.Unknown, method);

        var resolver = new NetworkConfigResolver(distro.Object, provider, NullLogger<NetworkConfigResolver>.Instance);
        var writer = await resolver.ResolveAsync();

        Assert.Equal(method, writer.ConfigMethod);
    }

    // ── fallback: writer absent → falls back to Unknown ────────────────

    [Fact]
    public async Task ResolveAsync_FallsBackToUnknown_WhenWriterForMethodMissing()
    {
        var distro = DistroReturning(NetworkConfigMethod.NetworkManager);
        // Only Unknown is registered; NetworkManager writer is missing.
        var provider = BuildProvider(NetworkConfigMethod.Unknown);

        var resolver = new NetworkConfigResolver(distro.Object, provider, NullLogger<NetworkConfigResolver>.Instance);
        var writer = await resolver.ResolveAsync();

        Assert.Equal(NetworkConfigMethod.Unknown, writer.ConfigMethod);
    }

    [Fact]
    public async Task ResolveAsync_DetectedUnknown_ResolvesToUnknownWriter()
    {
        var distro = DistroReturning(NetworkConfigMethod.Unknown);
        var provider = BuildProvider(NetworkConfigMethod.Unknown, NetworkConfigMethod.Netplan);

        var resolver = new NetworkConfigResolver(distro.Object, provider, NullLogger<NetworkConfigResolver>.Instance);
        var writer = await resolver.ResolveAsync();

        Assert.Equal(NetworkConfigMethod.Unknown, writer.ConfigMethod);
    }

    // ── cache: detector is consulted at most once ──────────────────────

    [Fact]
    public async Task ResolveAsync_CachesAfterFirstCall_DistroDetectorCalledOnce()
    {
        var distro = DistroReturning(NetworkConfigMethod.Netplan);
        var provider = BuildProvider(NetworkConfigMethod.Unknown, NetworkConfigMethod.Netplan);
        var resolver = new NetworkConfigResolver(distro.Object, provider, NullLogger<NetworkConfigResolver>.Instance);

        var a = await resolver.ResolveAsync();
        var b = await resolver.ResolveAsync();
        var c = await resolver.ResolveAsync();

        Assert.Same(a, b);
        Assert.Same(a, c);
        distro.Verify(s => s.DetectDistributionAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    // ── hard-fail: even Unknown writer missing → required-keyed throws ─

    [Fact]
    public async Task ResolveAsync_ThrowsWhenNeitherMethodWriterNorUnknownFallbackRegistered()
    {
        var distro = DistroReturning(NetworkConfigMethod.NetworkManager);
        // Empty container — no writers at all.
        var provider = BuildProvider();

        var resolver = new NetworkConfigResolver(distro.Object, provider, NullLogger<NetworkConfigResolver>.Instance);

        // GetRequiredKeyedService throws InvalidOperationException when nothing matches.
        await Assert.ThrowsAsync<InvalidOperationException>(() => resolver.ResolveAsync());
    }
}
