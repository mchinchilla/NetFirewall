using Microsoft.Extensions.Configuration;
using NetFirewall.Daemon;
using Xunit;

namespace NetFirewall.Tests.Tui;

/// <summary>
/// Pin the configuration shape that <c>install.sh</c> writes into
/// <c>/etc/netfirewall/daemon.env</c>. The installer renders these env vars:
///
/// <code>
///   Daemon__AcceptedPeerUids__0=&lt;web-uid&gt;
///   Daemon__AcceptedPeerUids__1=0
/// </code>
///
/// If the binding ever stops materialising the array (e.g. someone changes the
/// property name or breaks <c>int[]?</c> handling), the daemon would silently
/// ignore the configured peers and either accept everyone (dev mode) or
/// reject the Web entirely. Both failure modes are very bad and very quiet.
/// This test catches that at build time before any deploy.
/// </summary>
public class DaemonOptionsBindingTests
{
    [Fact]
    public void AcceptedPeerUids_BindsFromIndexedEnvVars()
    {
        // Mimics the EnvironmentVariablesConfigurationProvider's view of what
        // install.sh writes to daemon.env. Two-element list: Web UID + root.
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Daemon:AcceptedPeerUids:0"] = "1001",
                ["Daemon:AcceptedPeerUids:1"] = "0"
            })
            .Build();

        var opts = config.GetSection(DaemonOptions.SectionName).Get<DaemonOptions>();

        Assert.NotNull(opts);
        Assert.NotNull(opts!.AcceptedPeerUids);
        Assert.Equal(new[] { 1001, 0 }, opts.AcceptedPeerUids!);
    }

    [Fact]
    public void AcceptedPeerUids_AbsentFromConfig_DefaultOptionsAreNull()
    {
        // Dev path: the daemon falls back to `new DaemonOptions()` when no
        // section is bound (see Program.cs's `Get<DaemonOptions>() ?? new()`
        // pattern). The default constructor leaves both gates null, which
        // PeerCredentialMiddleware reads as "accept any peer".
        var defaults = new DaemonOptions();
        Assert.Null(defaults.AcceptedPeerUids);
        Assert.Null(defaults.ExpectedPeerUid);
    }

    [Fact]
    public void ExpectedPeerUid_LegacyKey_StillBinds_ForBackwardsCompat()
    {
        // Old daemon.env files set a single ExpectedPeerUid. The binding must
        // still work — installer upgrades shouldn't break running daemons until
        // they get re-installed.
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Daemon:ExpectedPeerUid"] = "1001"
            })
            .Build();

        var opts = config.GetSection(DaemonOptions.SectionName).Get<DaemonOptions>();
        Assert.Equal(1001, opts!.ExpectedPeerUid);
        Assert.Null(opts.AcceptedPeerUids);
    }

    [Fact]
    public void BothKeysPresent_BothBind_NeitherClobbersTheOther()
    {
        // Mid-upgrade scenario: env file has both. The middleware accepts a
        // peer matching EITHER, so as long as both are populated, both work.
        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Daemon:ExpectedPeerUid"] = "1001",
                ["Daemon:AcceptedPeerUids:0"] = "1001",
                ["Daemon:AcceptedPeerUids:1"] = "0"
            })
            .Build();

        var opts = config.GetSection(DaemonOptions.SectionName).Get<DaemonOptions>();
        Assert.Equal(1001, opts!.ExpectedPeerUid);
        Assert.Equal(new[] { 1001, 0 }, opts.AcceptedPeerUids!);
    }
}
