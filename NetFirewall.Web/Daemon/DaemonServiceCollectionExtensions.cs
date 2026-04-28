using NetFirewall.Services.Daemon;
using NetFirewall.Services.Auth;
using NetFirewall.Services.Network;
using NetFirewall.Web.Auth;

namespace NetFirewall.Web.Daemon;

/// <summary>
/// Centralizes the four DI swaps that depend on <see cref="DaemonClientOptions"/>.
/// Lives outside <c>Program.cs</c> so it can be unit-tested in isolation —
/// dev-vs-prod configuration drift caused at least one production crash and
/// one TOTP-cannot-enroll outage; the test suite pins the four resolutions
/// for every supported (Enabled, UseForTotp) combination.
///
/// The swaps:
///   1. <see cref="IDaemonClient"/>          — real client over UDS, or a
///                                              fail-graceful stub when daemon is off.
///   2. <see cref="IStaticRouteApplicator"/> — daemon-backed wrapper, or the
///                                              in-process applicator that shells out itself.
///   3. <see cref="INetworkConfigResolver"/> — daemon-decorator that proxies
///                                              writes, or the bare resolver.
///   4. <see cref="ITotpSecretCipher"/>      — daemon-backed (master key in
///                                              daemon process), or in-process AES.
/// </summary>
public static class DaemonServiceCollectionExtensions
{
    /// <summary>
    /// Apply the four daemon-vs-local swaps based on <paramref name="opts"/>.
    /// Caller must have already registered <see cref="NetworkConfigResolver"/>
    /// (concrete) and the keyed <see cref="INetworkConfigService"/> writers
    /// — those are independent of the daemon switch.
    /// </summary>
    public static IServiceCollection AddDaemonClientAndCiphers(
        this IServiceCollection services,
        DaemonClientOptions opts)
    {
        // Web-side token provider: reads the session cookie via IHttpContextAccessor.
        // Singleton — IHttpContextAccessor itself is singleton-safe (AsyncLocal
        // under the hood) and DaemonClient is also singleton, so the lifetime
        // chain stays consistent.
        services.AddSingleton<IDaemonSessionTokenProvider, WebDaemonSessionTokenProvider>();

        if (opts.Enabled)
        {
            // Daemon owns OS mutations.
            services.AddSingleton<IDaemonClient, DaemonClient>();
            services.AddScoped<IStaticRouteApplicator, DaemonStaticRouteApplicator>();
            services.AddSingleton<INetworkConfigResolver>(sp =>
                new DaemonResolverDecorator(sp.GetRequiredService<NetworkConfigResolver>(), sp));
        }
        else
        {
            // Legacy / dev path. Controllers still take IDaemonClient as a
            // dependency, so we hand them a stub that fails gracefully instead
            // of throwing at DI activation.
            services.AddSingleton<IDaemonClient, NullDaemonClient>();
            services.AddSingleton<INetworkConfigResolver>(sp => sp.GetRequiredService<NetworkConfigResolver>());
            services.AddScoped<IStaticRouteApplicator, StaticRouteApplicator>();
        }

        // TOTP cipher: daemon-backed only when the daemon is up AND opted into
        // TOTP duty (the operator may run a daemon for OS mutations but still
        // want the master key local — uncommon but valid).
        if (opts.Enabled && opts.UseForTotp)
        {
            services.AddSingleton<ITotpSecretCipher, DaemonTotpSecretCipher>();
        }
        else
        {
            services.AddSingleton<ITotpSecretCipher, AesGcmTotpSecretCipher>();
        }

        return services;
    }
}
