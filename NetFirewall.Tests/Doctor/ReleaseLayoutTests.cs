using NetFirewall.Doctor;
using NetFirewall.Doctor.Checks;
using NetFirewall.Models.System;
using Xunit;

namespace NetFirewall.Tests.Doctor;

/// <summary>
/// The release-bundle contract: build-bundle.sh stamps a version that every binary
/// prints the same way, writes VERSION into the release dir, and Doctor finds that
/// release from its own location (&lt;release&gt;/doctor/).
/// </summary>
public sealed class ReleaseLayoutTests : IDisposable
{
    private readonly string _root = Directory.CreateTempSubdirectory("nf-release-").FullName;

    public void Dispose() => Directory.Delete(_root, recursive: true);

    [Theory]
    [InlineData("v1.4.0", "1.4.0")]
    [InlineData("1.4.0-3-g97f88aa", "1.4.0-3-g97f88aa")]
    [InlineData("v1.4.0-3-g97f88aa-dirty", "1.4.0-3-g97f88aa-dirty")]
    [InlineData("97f88aa", "97f88aa")]                       // no tag yet: git describe --always
    [InlineData("1.0.0+97f88aa1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7", "1.0.0+97f88aa")] // SDK default
    [InlineData("vlan-build", "vlan-build")]                 // leading 'v' only stripped before a digit
    public void Normalize_prints_what_the_operator_tagged(string informational, string expected)
        => Assert.Equal(expected, BuildVersionText.Normalize(informational));

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
