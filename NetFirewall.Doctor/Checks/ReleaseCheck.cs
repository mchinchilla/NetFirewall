namespace NetFirewall.Doctor.Checks;

/// <summary>Which release is installed: the <c>VERSION</c> file build-bundle.sh writes into
/// every bundle, read from the release dir the units run (<c>$PREFIX/current</c>). Its
/// absence means the binaries did not come from a bundle — the legacy
/// <c>install.sh</c>/<c>.deb</c> layout or a hand publish — so there is no version to track.
/// Pure file read; works off Linux too.</summary>
public sealed class ReleaseCheck : ICheck
{
    public string Category => "Paths";
    public string Name => "Installed release";
    public IReadOnlyList<string> Services => Array.Empty<string>();

    public Task<CheckResult> RunAsync(DoctorContext ctx, CancellationToken ct)
    {
        string? version = null;
        try
        {
            if (File.Exists(ctx.ReleaseVersionPath))
                version = File.ReadAllText(ctx.ReleaseVersionPath).Trim();
        }
        catch { /* unreadable — treated as absent */ }

        if (string.IsNullOrEmpty(version))
            return Task.FromResult(CheckResult.Warn(
                $"no VERSION file under {ctx.Prefix} — not installed from a release bundle",
                remedy: "Install the release tarball with ./setup.sh so the version is tracked (and --rollback works)."));

        return Task.FromResult(CheckResult.Pass($"release {version} ({ctx.Prefix})"));
    }
}
