namespace NetFirewall.Doctor.Checks;

/// <summary>Both env files exist and are readable; daemon.env should be 0600.</summary>
public sealed class EnvFilesCheck : ICheck
{
    public string Category => "Env";
    public string Name => "Env files present";
    public IReadOnlyList<string> Services => Array.Empty<string>();

    public Task<CheckResult> RunAsync(DoctorContext ctx, CancellationToken ct)
    {
        var missing = new List<string>();
        if (ctx.DaemonEnv is null) missing.Add(ctx.DaemonEnvPath);
        if (ctx.WebEnv is null) missing.Add(ctx.WebEnvPath);

        if (missing.Count > 0)
        {
            return Task.FromResult(CheckResult.Fail(
                $"Missing or unreadable: {string.Join(", ", missing)}",
                remedy: "Run sudo deploy/install.sh, or create the env files from deploy/env/*.template."));
        }

        // Mode sanity (Unix only — File.GetUnixFileMode is unsupported on Windows).
        // Use OperatingSystem.IsLinux() (not ctx.IsLinux) so the CA1416 analyzer can
        // see the platform guard statically.
        if (OperatingSystem.IsLinux())
        {
            try
            {
                var mode = File.GetUnixFileMode(ctx.DaemonEnvPath);
                var groupOrOther = mode & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.OtherRead | UnixFileMode.OtherWrite);
                if (groupOrOther != 0)
                    return Task.FromResult(CheckResult.Warn(
                        $"daemon.env is group/other-accessible ({mode}); it holds the master key + DB password.",
                        remedy: $"chmod 0600 {ctx.DaemonEnvPath}"));
            }
            catch { /* best effort */ }
        }

        return Task.FromResult(CheckResult.Pass("daemon.env and web.env present"));
    }
}
