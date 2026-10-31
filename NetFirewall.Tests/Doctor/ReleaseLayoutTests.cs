using NetFirewall.Doctor;
using NetFirewall.Doctor.Checks;
using NetFirewall.Models.System;
using NetFirewall.Web.Models.Shared;
using Xunit;

namespace NetFirewall.Tests.Doctor;

/// <summary>
/// The release-bundle contract: build-bundle.sh stamps a version + commit that every
/// binary reads the same way (and the Web badge shortens), writes VERSION into the
/// release dir, and Doctor finds that release from its own location (&lt;release&gt;/doctor/).
/// </summary>
public sealed class ReleaseLayoutTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("nf-release-").FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Theory]
    //          informational version                                      version                    commit     release dirty
    [InlineData("v0.6.1", "0.6.1", null, true, false)]
    [InlineData("0.6.1+97f88aa1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7", "0.6.1", "97f88aa", true, false)]   // bundle: describe + SourceRevisionId
    [InlineData("0.6.1-3-g97f88aa", "0.6.1-3-g97f88aa", "97f88aa", false, false)]
    [InlineData("v0.6.1-3-g97f88aa-dirty+97f88aa1c2d3", "0.6.1-3-g97f88aa-dirty", "97f88aa", false, true)]
    [InlineData("97f88aa", "97f88aa", "97f88aa", false, false)]                                     // no tag yet
    [InlineData("1.0.0+97F88AA1C2D3E4F5", "1.0.0", "97f88aa", true, false)]                          // plain dotnet build
    [InlineData("0.6.1+unknown", "0.6.1", null, true, false)]                                         // no git on the build box
    [InlineData("vlan-build", "vlan-build", null, false, false)]                                      // 'v' only stripped before a digit
    public void Parse_splits_version_and_commit(string informational, string version, string? commit, bool release, bool dirty)
        => Assert.Equal(new BuildInfo(version, commit, release, dirty), BuildVersionText.Parse(informational));

    [Theory]
    [InlineData("0.6.1", "0.6.1")]
    [InlineData("0.6.1-3-g97f88aa", "0.6.1+3")]
    [InlineData("0.6.1-3-g97f88aa-dirty", "0.6.1+3")]
    [InlineData("97f88aa-dirty", "97f88aa")]
    public void Badge_prints_a_short_version(string version, string display)
    {
        var badge = new VersionBadgeViewModel { Build = BuildVersionText.Parse(version), Environment = "Production" };
        Assert.Equal(display, badge.DisplayVersion);
    }

    [Fact]
    public void Badge_does_not_repeat_the_sha_when_there_is_no_tag()
    {
        var badge = new VersionBadgeViewModel { Build = BuildVersionText.Parse("97f88aa"), Environment = "Production" };
        Assert.False(badge.ShowCommit);
        Assert.True(new VersionBadgeViewModel { Build = BuildVersionText.Parse("0.6.1+97f88aa1"), Environment = "Production" }.ShowCommit);
    }

    [Fact]
    public void DetectPrefix_is_the_release_holding_doctor_and_daemon()
    {
        var release = Path.Combine(_root, "releases", "1.4.0");
        Directory.CreateDirectory(Path.Combine(release, "daemon"));
        Directory.CreateDirectory(Path.Combine(release, "doctor"));

        Assert.Equal(release, DoctorContext.DetectPrefix(Path.Combine(release, "doctor") + Path.DirectorySeparatorChar));
    }

    [Fact]
    public void DetectPrefix_falls_back_outside_a_release()
    {
        var bin = Path.Combine(_root, "bin", "Debug");
        Directory.CreateDirectory(bin);

        Assert.Equal(DoctorContext.DefaultPrefix, DoctorContext.DetectPrefix(bin));
    }

    [Fact]
    public async Task ReleaseCheck_reports_the_bundle_version()
    {
        await File.WriteAllTextAsync(Path.Combine(_root, "VERSION"), "1.4.0-3-g97f88aa\n");

        var r = await new ReleaseCheck().RunAsync(new DoctorContext { Prefix = _root }, default);

        Assert.Equal(CheckStatus.Pass, r.Status);
        Assert.Contains("1.4.0-3-g97f88aa", r.Message);
    }

    [Fact]
    public async Task ReleaseCheck_warns_on_a_layout_without_VERSION()
    {
        var r = await new ReleaseCheck().RunAsync(new DoctorContext { Prefix = _root }, default);

        Assert.Equal(CheckStatus.Warn, r.Status);
        Assert.NotNull(r.Remedy);
    }

    [Fact]
    public async Task Dhcp_checks_skip_when_the_host_never_enabled_dhcp()
    {
        // Every release ships dhcp-server/ with a dev appsettings.json; on a host without the
        // unit or dhcp.env, validating that file would report a bogus DB failure.
        var ctx = new DoctorContext
        {
            DhcpEnabled = false,
            IsLinux = true,
            DhcpConnectionString = "Host=127.0.0.1;Username=postgres;Password=dev",
            DhcpInterfaces = new[] { "ens256" },
        };

        foreach (var check in new ICheck[] { new DhcpConfigCheck(), new DhcpInterfaceCheck(), new DhcpDatabaseCheck() })
        {
            var r = await check.RunAsync(ctx, default);
            Assert.Equal(CheckStatus.Skip, r.Status);
            Assert.Equal(DoctorContext.DhcpNotEnabled, r.Message);
        }
    }
}
