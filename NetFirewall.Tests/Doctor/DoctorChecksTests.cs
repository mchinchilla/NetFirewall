using NetFirewall.Doctor;
using NetFirewall.Doctor.Checks;
using Xunit;

namespace NetFirewall.Tests.Doctor;

/// <summary>
/// Pure-logic coverage for the Doctor's checks: env-file parsing, master-key sync
/// (the production incident), and required-vars detection. No host/DB/socket needed
/// — checks are fed in-memory DoctorContext fixtures.
/// </summary>
public sealed class DoctorChecksTests
{
    // ── EnvFile.Parse ──
    [Fact]
    public void EnvFile_parses_keys_ignores_comments_and_blanks()
    {
        var env = EnvFile.Parse(new[]
        {
            "# comment",
            "",
            "KEY=value",
            "NETFIREWALL_MASTER_KEY=abc+def/123=",   // '=' inside the value is preserved
            "   SPACED = trimmed key  ",
        });

        Assert.Equal("value", env["KEY"]);
        Assert.Equal("abc+def/123=", env["NETFIREWALL_MASTER_KEY"]); // base64 padding kept
        // The whole line is trimmed first, then split on '=', then the key is trimmed:
        // "SPACED = trimmed key" → key "SPACED", value " trimmed key" (leading space kept).
        Assert.Equal(" trimmed key", env["SPACED"]);
        Assert.False(env.ContainsKey("# comment"));
    }

    private static DoctorContext Ctx(
        IReadOnlyDictionary<string, string>? daemon,
        IReadOnlyDictionary<string, string>? web)
        => new() { DaemonEnv = daemon, WebEnv = web, IsLinux = false };

    private static Dictionary<string, string> Env(params (string, string)[] kv)
        => kv.ToDictionary(x => x.Item1, x => x.Item2, StringComparer.Ordinal);

    // ── MasterKeySyncCheck ──
    [Fact]
    public async Task MasterKeySync_passes_when_identical()
    {
        var ctx = Ctx(Env(("NETFIREWALL_MASTER_KEY", "K1")), Env(("NETFIREWALL_MASTER_KEY", "K1")));
        var r = await new MasterKeySyncCheck().RunAsync(ctx, default);
        Assert.Equal(CheckStatus.Pass, r.Status);
    }

    [Fact]
    public async Task MasterKeySync_fails_when_daemon_missing_the_incident()
    {
        // The exact production incident: web has it, daemon doesn't.
        var ctx = Ctx(Env(("Daemon__SocketPath", "/x")), Env(("NETFIREWALL_MASTER_KEY", "K1")));
        var r = await new MasterKeySyncCheck().RunAsync(ctx, default);
        Assert.Equal(CheckStatus.Fail, r.Status);
        Assert.Contains("MISSING from daemon.env", r.Message);
        Assert.NotNull(r.Remedy);
    }

    [Fact]
    public async Task MasterKeySync_fails_when_keys_differ()
    {
        var ctx = Ctx(Env(("NETFIREWALL_MASTER_KEY", "K1")), Env(("NETFIREWALL_MASTER_KEY", "K2")));
        var r = await new MasterKeySyncCheck().RunAsync(ctx, default);
        Assert.Equal(CheckStatus.Fail, r.Status);
        Assert.Contains("DIFFERS", r.Message);
    }

    [Fact]
    public async Task MasterKeySync_fails_when_both_missing()
    {
        var ctx = Ctx(Env(("X", "1")), Env(("Y", "2")));
        var r = await new MasterKeySyncCheck().RunAsync(ctx, default);
        Assert.Equal(CheckStatus.Fail, r.Status);
        Assert.Contains("BOTH", r.Message);
    }

    [Fact]
    public async Task MasterKeySync_treats_template_placeholder_as_missing()
    {
        var ctx = Ctx(Env(("NETFIREWALL_MASTER_KEY", "__REPLACE_MASTER_KEY__")),
                      Env(("NETFIREWALL_MASTER_KEY", "K1")));
        var r = await new MasterKeySyncCheck().RunAsync(ctx, default);
        Assert.Equal(CheckStatus.Fail, r.Status);
        Assert.Contains("MISSING from daemon.env", r.Message);
    }

    [Fact]
    public async Task MasterKeySync_skips_when_a_file_is_absent()
    {
        var ctx = Ctx(null, Env(("NETFIREWALL_MASTER_KEY", "K1")));
        var r = await new MasterKeySyncCheck().RunAsync(ctx, default);
        Assert.Equal(CheckStatus.Skip, r.Status);
    }

    // ── RequiredVarsCheck ──
    [Fact]
    public async Task RequiredVars_fails_on_placeholder_value()
    {
        var ctx = Ctx(Env(("ConnectionStrings__DefaultConnection", "__REPLACE__")), null);
        var check = new RequiredVarsCheck("daemon", c => c.DaemonEnv, c => "daemon.env",
            "ConnectionStrings__DefaultConnection");
        var r = await check.RunAsync(ctx, default);
        Assert.Equal(CheckStatus.Fail, r.Status);
        Assert.Contains("ConnectionStrings__DefaultConnection", r.Message);
    }

    [Fact]
    public async Task RequiredVars_passes_when_all_present()
    {
        var ctx = Ctx(Env(("A", "1"), ("B", "2")), null);
        var check = new RequiredVarsCheck("daemon", c => c.DaemonEnv, c => "daemon.env", "A", "B");
        var r = await check.RunAsync(ctx, default);
        Assert.Equal(CheckStatus.Pass, r.Status);
    }
}
