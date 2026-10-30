namespace NetFirewall.Doctor.Checks;

/// <summary>Deployment directories exist (binaries published, runtime + state dirs).
/// Linux-only — Skips elsewhere.</summary>
public sealed class PathsCheck : ICheck
{
    public string Category => "Paths";
    public string Name => "Deployment layout";
    public IReadOnlyList<string> Services => Array.Empty<string>();

    public Task<CheckResult> RunAsync(DoctorContext ctx, CancellationToken ct)
    {
        if (!ctx.IsLinux)
            return Task.FromResult(CheckResult.Skip("not applicable off Linux"));

        var required = new (string Path, string What)[]
        {
            (Path.Combine(ctx.Prefix, "daemon"), "daemon binaries"),
            (Path.Combine(ctx.Prefix, "web"), "web binaries"),
            (ctx.EtcDir, "config dir"),
            (ctx.StateDir, "state dir"),
        };

        var missing = required.Where(r => !Directory.Exists(r.Path)).ToList();
        if (missing.Count > 0)
            return Task.FromResult(CheckResult.Fail(
                $"missing: {string.Join(", ", missing.Select(m => $"{m.Path} ({m.What})"))}",
                remedy: "Run ./setup.sh from the release bundle. If your prefix differs, pass --prefix <PREFIX>/current."));

        return Task.FromResult(CheckResult.Pass($"binaries + dirs present under {ctx.Prefix} and {ctx.EtcDir}"));
    }
}
