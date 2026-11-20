using NetFirewall.Doctor;
using NetFirewall.Doctor.Checks;

namespace NetFirewall.Tests.Doctor;

/// <summary>The data grids live in same-origin iframes; a DENY frame policy blanks them.</summary>
public sealed class NginxFramingCheckTests : IDisposable
{
    private readonly string _dir = Directory.CreateTempSubdirectory("nf-nginx-").FullName;

    public void Dispose() => Directory.Delete(_dir, recursive: true);

    private async Task<CheckResult> RunAsync(string? site)
    {
        if (site is not null) await File.WriteAllTextAsync(Path.Combine(_dir, "netfirewall.conf"), site);
        return await new NginxFramingCheck(_dir).RunAsync(new DoctorContext(), CancellationToken.None);
    }

    [Fact]
    public async Task DenyHeader_Warns_WithRemedy()
    {
        var r = await RunAsync("server {\n    add_header X-Frame-Options           \"DENY\" always;\n}");
        Assert.Equal(CheckStatus.Warn, r.Status);
        Assert.Contains("SAMEORIGIN", r.Remedy);
    }

    [Fact]
    public async Task SameOriginHeader_Passes()
    {
        var r = await RunAsync("server {\n    add_header X-Frame-Options \"SAMEORIGIN\" always;\n}");
        Assert.Equal(CheckStatus.Pass, r.Status);
    }

    [Fact]
    public async Task CommentedOutDeny_Passes()
    {
        var r = await RunAsync("server {\n    # add_header X-Frame-Options \"DENY\" always;\n}");
        Assert.Equal(CheckStatus.Pass, r.Status);
    }

    [Fact]
    public async Task NoSite_Skips() => Assert.Equal(CheckStatus.Skip, (await RunAsync(null)).Status);

    [Fact]
    public async Task ShippedTemplates_DoNotDenyFraming()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "deploy", "nginx"))) dir = dir.Parent;
        Assert.NotNull(dir);
        foreach (var f in Directory.EnumerateFiles(Path.Combine(dir!.FullName, "deploy", "nginx")))
            File.Copy(f, Path.Combine(_dir, "netfirewall-" + Path.GetFileName(f)));
        Assert.Equal(CheckStatus.Pass, (await new NginxFramingCheck(_dir).RunAsync(new DoctorContext(), CancellationToken.None)).Status);
    }
}
