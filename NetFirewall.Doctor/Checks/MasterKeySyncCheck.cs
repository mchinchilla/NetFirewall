namespace NetFirewall.Doctor.Checks;

/// <summary>
/// The master key MUST be present in both env files and byte-identical — the
/// daemon and Web decrypt the same TOTP secrets. This is the exact failure that
/// broke the web terminal in production (daemon.env missing the key while web.env
/// had it). See docs/master-key.md.
/// </summary>
public sealed class MasterKeySyncCheck : ICheck
{
    private const string Key = "NETFIREWALL_MASTER_KEY";

    public string Category => "Master key";
    public string Name => "daemon ↔ web key in sync";
    public IReadOnlyList<string> Services => Array.Empty<string>();

    public Task<CheckResult> RunAsync(DoctorContext ctx, CancellationToken ct)
    {
        if (ctx.DaemonEnv is null || ctx.WebEnv is null)
            return Task.FromResult(CheckResult.Skip("one or both env files absent (see Env files check)"));

        ctx.DaemonEnv.TryGetValue(Key, out var daemonKey);
        ctx.WebEnv.TryGetValue(Key, out var webKey);
        daemonKey = daemonKey?.Trim();
        webKey = webKey?.Trim();

        bool daemonHas = !string.IsNullOrEmpty(daemonKey) && daemonKey != "__REPLACE_MASTER_KEY__";
        bool webHas = !string.IsNullOrEmpty(webKey) && webKey != "__REPLACE_MASTER_KEY__";

        if (!daemonHas && !webHas)
            return Task.FromResult(CheckResult.Fail(
                "master key missing from BOTH env files",
                remedy: "Generate one (openssl rand -base64 32) and put the SAME value in both. See docs/master-key.md."));

        if (!daemonHas)
            return Task.FromResult(CheckResult.Fail(
                "master key present in web.env but MISSING from daemon.env — daemon-side TOTP (terminal, crypto) will fail",
                remedy: $"grep '^{Key}=' {ctx.WebEnvPath} >> {ctx.DaemonEnvPath} && chmod 0600 {ctx.DaemonEnvPath} && systemctl restart netfirewall-daemon"));

        if (!webHas)
            return Task.FromResult(CheckResult.Fail(
                "master key present in daemon.env but MISSING from web.env",
                remedy: $"Copy the {Key} line from {ctx.DaemonEnvPath} into {ctx.WebEnvPath}."));

        if (!string.Equals(daemonKey, webKey, StringComparison.Ordinal))
            return Task.FromResult(CheckResult.Fail(
                "master key DIFFERS between daemon.env and web.env — every TOTP code will be rejected",
                remedy: "Make them identical (use the value that encrypted the existing secrets). See docs/master-key.md."));

        return Task.FromResult(CheckResult.Pass("identical master key in both files"));
    }
}
