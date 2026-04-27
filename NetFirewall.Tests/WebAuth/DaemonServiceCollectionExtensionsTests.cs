using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Services.Auth;
using NetFirewall.Services.Network;
using NetFirewall.Web.Auth;
using NetFirewall.Web.Daemon;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// Pins the DI swap that <see cref="DaemonServiceCollectionExtensions.AddDaemonClientAndCiphers"/>
/// performs based on <see cref="DaemonClientOptions"/>. Two production outages
/// were caused by config drift between Program.cs and appsettings:
///
///   1. Daemon enabled in dev (no socket) → controllers crashed at activation.
///   2. UseForTotp wired to the daemon path while daemon was off → enrollment
///      failed with a confusing socket error.
///
/// Every supported (Enabled, UseForTotp) combination is asserted here so a
/// future refactor of the swap logic can't silently regress these.
/// </summary>
public class DaemonServiceCollectionExtensionsTests
{
    /// <summary>
    /// Build a service collection with the bare-minimum dependencies the swap
    /// extension needs to resolve fully. Mocks anything platform-specific
    /// (IHostEnvironment, IConfiguration with master key) so tests run on any host.
    /// </summary>
    private static ServiceCollection BaseServices()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddHttpContextAccessor();

        // Concrete resolver + its constructor deps.
        services.AddSingleton(new Mock<ILinuxDistroService>().Object);
        services.AddSingleton<NetworkConfigResolver>();

        // AesGcmTotpSecretCipher needs IConfiguration + IHostEnvironment.
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                // 32-byte base64 key so the cipher constructor doesn't throw.
                ["Auth:MasterKey"] = Convert.ToBase64String(new byte[32])
            })
            .Build();
        services.AddSingleton<IConfiguration>(config);

        var env = new Mock<IHostEnvironment>();
        env.SetupGet(e => e.EnvironmentName).Returns("Development");
        services.AddSingleton(env.Object);

        return services;
    }

    /// <summary>Inspect the registered descriptor for a service interface.</summary>
    private static ServiceDescriptor DescriptorFor<T>(IServiceCollection services) =>
        services.Last(d => d.ServiceType == typeof(T));

    // ── Daemon enabled: full daemon-backed wiring ──────────────────────

    [Fact]
    public void Enabled_True_UseForTotp_True_RegistersAllDaemonImplementations()
    {
        var services = BaseServices();
        services.AddDaemonClientAndCiphers(new DaemonClientOptions
        {
            Enabled = true, UseForTotp = true, SocketPath = "/tmp/test.sock"
        });

        // Inspect descriptors directly — the factory-based ones won't have
        // ImplementationType, so we resolve through the provider when needed.
        Assert.Equal(typeof(DaemonClient), DescriptorFor<IDaemonClient>(services).ImplementationType);
        Assert.Equal(typeof(DaemonStaticRouteApplicator), DescriptorFor<IStaticRouteApplicator>(services).ImplementationType);
        Assert.Equal(typeof(DaemonTotpSecretCipher), DescriptorFor<ITotpSecretCipher>(services).ImplementationType);

        // INetworkConfigResolver uses a factory — verify by resolving.
        var sp = services.BuildServiceProvider();
        var resolver = sp.GetRequiredService<INetworkConfigResolver>();
        Assert.IsType<DaemonResolverDecorator>(resolver);
    }

    [Fact]
    public void Enabled_True_UseForTotp_False_OverridesTotpToInProcessAes()
    {
        // Operator wants daemon for OS mutations but keeps the master key local
        // (uncommon, but the option exists).
        var services = BaseServices();
        services.AddDaemonClientAndCiphers(new DaemonClientOptions
        {
            Enabled = true, UseForTotp = false
        });

        Assert.Equal(typeof(DaemonClient), DescriptorFor<IDaemonClient>(services).ImplementationType);
        Assert.Equal(typeof(DaemonStaticRouteApplicator), DescriptorFor<IStaticRouteApplicator>(services).ImplementationType);
        // TOTP path falls back to in-process AES.
        Assert.Equal(typeof(AesGcmTotpSecretCipher), DescriptorFor<ITotpSecretCipher>(services).ImplementationType);
    }

    // ── Daemon disabled: in-process / null-stub wiring (the dev path) ──

    [Fact]
    public void Enabled_False_RegistersNullDaemonClient_AndInProcessImplementations()
    {
        var services = BaseServices();
        services.AddDaemonClientAndCiphers(new DaemonClientOptions { Enabled = false });

        Assert.Equal(typeof(NullDaemonClient), DescriptorFor<IDaemonClient>(services).ImplementationType);
        Assert.Equal(typeof(StaticRouteApplicator), DescriptorFor<IStaticRouteApplicator>(services).ImplementationType);
        Assert.Equal(typeof(AesGcmTotpSecretCipher), DescriptorFor<ITotpSecretCipher>(services).ImplementationType);

        // The bare resolver (no decorator).
        var sp = services.BuildServiceProvider();
        var resolver = sp.GetRequiredService<INetworkConfigResolver>();
        Assert.IsType<NetworkConfigResolver>(resolver);
    }

    [Fact]
    public void Enabled_False_UseForTotp_True_StillFallsBackToAes()
    {
        // Belt-and-suspenders: even if the operator left UseForTotp=true on
        // accident, Enabled=false must short-circuit to AES (no daemon to call).
        var services = BaseServices();
        services.AddDaemonClientAndCiphers(new DaemonClientOptions
        {
            Enabled = false, UseForTotp = true
        });

        Assert.Equal(typeof(NullDaemonClient), DescriptorFor<IDaemonClient>(services).ImplementationType);
        Assert.Equal(typeof(AesGcmTotpSecretCipher), DescriptorFor<ITotpSecretCipher>(services).ImplementationType);
    }

    // ── Activation smoke test: NullDaemonClient is callable, no DaemonClient ───

    [Fact]
    public void Enabled_False_IDaemonClient_Resolvable_WithoutSocketOrHttp()
    {
        var services = BaseServices();
        services.AddDaemonClientAndCiphers(new DaemonClientOptions { Enabled = false });

        var sp = services.BuildServiceProvider();

        // The whole point: controllers can take IDaemonClient as a constructor
        // dependency and the container can hand them an instance even though
        // the daemon binary isn't running. Pre-fix this threw at activation.
        var client = sp.GetRequiredService<IDaemonClient>();
        Assert.IsType<NullDaemonClient>(client);
    }

    [Fact]
    public async Task NullDaemonClient_ApplyOps_ReturnUnreachableFailure_NotThrow()
    {
        // Sanity: the dev-mode stub doesn't crash when controllers invoke its
        // apply methods. They get a clean ServiceResponse.Fail("daemon disabled")
        // that can be surfaced as a toast.
        var services = BaseServices();
        services.AddDaemonClientAndCiphers(new DaemonClientOptions { Enabled = false });

        var sp = services.BuildServiceProvider();
        var client = sp.GetRequiredService<IDaemonClient>();

        var result = await client.ApplyFirewallAsync();

        Assert.False(result.Success);
        Assert.Contains("daemon", result.Message, StringComparison.OrdinalIgnoreCase);
    }

    // ── Default options sanity ─────────────────────────────────────────

    [Fact]
    public void DefaultDaemonClientOptions_RegistersDaemonPath()
    {
        // The class default is Enabled=true and UseForTotp=true (production
        // posture). Ship-it scenario: appsettings.json stays at defaults,
        // daemon is up, everything resolves to the daemon impls.
        var services = BaseServices();
        services.AddDaemonClientAndCiphers(new DaemonClientOptions());

        Assert.Equal(typeof(DaemonClient), DescriptorFor<IDaemonClient>(services).ImplementationType);
        Assert.Equal(typeof(DaemonTotpSecretCipher), DescriptorFor<ITotpSecretCipher>(services).ImplementationType);
    }
}
