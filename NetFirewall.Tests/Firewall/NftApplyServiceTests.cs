using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Processes;
using Xunit;

namespace NetFirewall.Tests.Firewall;

public class NftApplyServiceTests : IDisposable
{
    private readonly string _tempRoot;
    private readonly string _configPath;
    private readonly string _backupDir;
    private readonly Mock<IFirewallService> _firewall = new();
    private readonly Mock<IProcessRunner> _runner = new();

    public NftApplyServiceTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), "nft-apply-tests-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempRoot);
        _configPath = Path.Combine(_tempRoot, "nftables.conf");
        _backupDir  = Path.Combine(_tempRoot, "backups");
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempRoot, recursive: true); } catch { /* best-effort */ }
    }

    private NftApplyService CreateSvc(NftApplyOptions? opts = null) =>
        new(
            _firewall.Object,
            _runner.Object,
            NullLogger<NftApplyService>.Instance,
            Options.Create(opts ?? new NftApplyOptions
            {
                NftPath = "/usr/sbin/nft",
                ConfigPath = _configPath,
                BackupDirectory = _backupDir,
                CommandTimeoutSeconds = 5,
                CreateBackupBeforeApply = true
            }));

    private void StubRunner(int exitCode, string output = "", string error = "")
        => _runner
            .Setup(r => r.RunAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessResult(exitCode, output, error));

    // ── ApplyFromFileAsync ──────────────────────────────────────────────

    [Fact]
    public async Task ApplyFromFileAsync_ReturnsErrorWhenFileMissing_AndDoesNotInvokeNft()
    {
        var svc = CreateSvc();
        var result = await svc.ApplyFromFileAsync(Path.Combine(_tempRoot, "missing.conf"));

        Assert.False(result.Success);
        Assert.Equal(-1, result.ExitCode);
        Assert.Contains("not found", result.Error);
        _runner.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task ApplyFromFileAsync_InvokesNftWithMinusFAndPath_OnSuccess()
    {
        var path = Path.Combine(_tempRoot, "rules.conf");
        await File.WriteAllTextAsync(path, "table inet filter {}");
        StubRunner(exitCode: 0, output: "ok");

        var svc = CreateSvc();
        var result = await svc.ApplyFromFileAsync(path);

        Assert.True(result.Success);
        Assert.Equal(0, result.ExitCode);
        Assert.Equal("ok", result.Output);
        _runner.Verify(r => r.RunAsync(
            "/usr/sbin/nft",
            $"-f {path}",
            TimeSpan.FromSeconds(5),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ApplyFromFileAsync_PropagatesNftFailure()
    {
        var path = Path.Combine(_tempRoot, "bad.conf");
        await File.WriteAllTextAsync(path, "garbage");
        StubRunner(exitCode: 1, error: "syntax error at line 1");

        var svc = CreateSvc();
        var result = await svc.ApplyFromFileAsync(path);

        Assert.False(result.Success);
        Assert.Equal(1, result.ExitCode);
        Assert.Contains("syntax error", result.Error);
    }

    // ── ValidateConfigurationAsync ──────────────────────────────────────

    [Fact]
    public async Task ValidateConfigurationAsync_WritesTempFile_InvokesNftMinusC_AndCleansUp()
    {
        StubRunner(exitCode: 0);
        var svc = CreateSvc();

        var result = await svc.ValidateConfigurationAsync("table inet filter {}");

        Assert.True(result.Success);
        // Verify nft was called with `-c -f <something>`.
        _runner.Verify(r => r.RunAsync(
            "/usr/sbin/nft",
            It.Is<string>(args => args.StartsWith("-c -f ") && args.Contains("nft-validate-")),
            It.IsAny<TimeSpan?>(),
            It.IsAny<CancellationToken>()), Times.Once);
        // Temp validation files should not linger.
        var leftovers = Directory.GetFiles(Path.GetTempPath(), "nft-validate-*.conf");
        Assert.Empty(leftovers);
    }

    [Fact]
    public async Task ValidateConfigurationAsync_ReturnsErrorOnInvalidConfig()
    {
        StubRunner(exitCode: 1, error: "Error: syntax error");
        var svc = CreateSvc();

        var result = await svc.ValidateConfigurationAsync("not a valid ruleset");

        Assert.False(result.Success);
        Assert.Equal(1, result.ExitCode);
        Assert.Contains("syntax error", result.Error);
    }

    // ── BackupCurrentRulesetAsync ───────────────────────────────────────

    [Fact]
    public async Task BackupCurrentRulesetAsync_WritesTimestampedFile_WithRulesetContents()
    {
        StubRunner(exitCode: 0, output: "table inet filter { chain input { } }");
        var svc = CreateSvc();

        var path = await svc.BackupCurrentRulesetAsync();

        Assert.True(File.Exists(path));
        Assert.StartsWith(_backupDir, path);
        Assert.Matches(@"nftables-\d{8}-\d{6}\.conf$", Path.GetFileName(path));
        var content = await File.ReadAllTextAsync(path);
        Assert.Contains("table inet filter", content);
    }

    [Fact]
    public async Task BackupCurrentRulesetAsync_StillWritesFile_EvenWhenNftFails()
    {
        // If `nft list ruleset` fails, the service writes "# Error: ..." to the
        // backup. That's deliberate — we always produce *something* so the
        // restore path has a known artifact, even if degenerate.
        StubRunner(exitCode: 1, error: "permission denied");
        var svc = CreateSvc();

        var path = await svc.BackupCurrentRulesetAsync();

        Assert.True(File.Exists(path));
        var content = await File.ReadAllTextAsync(path);
        Assert.StartsWith("# Error:", content);
    }

    // ── RestoreFromBackupAsync ──────────────────────────────────────────

    [Fact]
    public async Task RestoreFromBackupAsync_ReturnsErrorWhenBackupMissing()
    {
        var svc = CreateSvc();
        var result = await svc.RestoreFromBackupAsync(Path.Combine(_tempRoot, "nope.conf"));

        Assert.False(result.Success);
        Assert.Equal(-1, result.ExitCode);
        Assert.Contains("not found", result.Error);
        _runner.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task RestoreFromBackupAsync_DelegatesToApplyFromFile_WhenBackupExists()
    {
        var backup = Path.Combine(_tempRoot, "snapshot.conf");
        await File.WriteAllTextAsync(backup, "table inet filter {}");
        StubRunner(exitCode: 0);

        var svc = CreateSvc();
        var result = await svc.RestoreFromBackupAsync(backup);

        Assert.True(result.Success);
        _runner.Verify(r => r.RunAsync(
            "/usr/sbin/nft",
            $"-f {backup}",
            It.IsAny<TimeSpan?>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    // ── ApplyConfigurationAsync (orchestrator) ──────────────────────────

    [Fact]
    public async Task ApplyConfigurationAsync_FailsAtValidation_DoesNotBackupOrApply()
    {
        _firewall.Setup(f => f.GenerateNftablesConfigAsync(It.IsAny<CancellationToken>()))
                 .ReturnsAsync("invalid ruleset");
        StubRunner(exitCode: 1, error: "syntax error"); // every nft call fails

        var svc = CreateSvc();
        var result = await svc.ApplyConfigurationAsync();

        Assert.False(result.Success);
        Assert.Contains("syntax error", result.Error);
        // Validation runs (-c -f), but neither apply nor backup happen.
        _runner.Verify(r => r.RunAsync(
            "/usr/sbin/nft",
            It.Is<string>(a => a.StartsWith("-c -f ")),
            It.IsAny<TimeSpan?>(),
            It.IsAny<CancellationToken>()), Times.Once);
        _runner.Verify(r => r.RunAsync(
            "/usr/sbin/nft",
            "list ruleset",
            It.IsAny<TimeSpan?>(),
            It.IsAny<CancellationToken>()), Times.Never);
        _firewall.Verify(f => f.LogAuditAsync(
            It.IsAny<string>(), It.IsAny<Guid>(), It.IsAny<string>(),
            It.IsAny<object?>(), It.IsAny<object?>(), It.IsAny<string?>(),
            It.IsAny<CancellationToken>()), Times.Never);
        Assert.False(File.Exists(_configPath));
    }

    [Fact]
    public async Task ApplyConfigurationAsync_HappyPath_BacksUp_Writes_Applies_AndAudits()
    {
        const string config = "table inet filter { chain input { } }";
        _firewall.Setup(f => f.GenerateNftablesConfigAsync(It.IsAny<CancellationToken>()))
                 .ReturnsAsync(config);
        StubRunner(exitCode: 0, output: "table inet filter {}"); // every nft call succeeds

        var svc = CreateSvc();
        var result = await svc.ApplyConfigurationAsync();

        Assert.True(result.Success, result.Error);
        Assert.NotNull(result.BackupPath);
        Assert.True(File.Exists(result.BackupPath));
        // Config was written to the configured path before apply.
        Assert.True(File.Exists(_configPath));
        Assert.Equal(config, await File.ReadAllTextAsync(_configPath));
        _firewall.Verify(f => f.LogAuditAsync(
            "fw_system", Guid.Empty, "APPLY_CONFIG",
            It.IsAny<object?>(), It.IsAny<object?>(), It.IsAny<string?>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ApplyConfigurationAsync_ApplyFails_TriggersRollbackFromBackup()
    {
        const string config = "table inet filter {}";
        _firewall.Setup(f => f.GenerateNftablesConfigAsync(It.IsAny<CancellationToken>()))
                 .ReturnsAsync(config);

        // Sequence: validation OK, list ruleset OK (for backup), apply fails, restore OK.
        var seq = new Queue<ProcessResult>(new[]
        {
            new ProcessResult(0, "", ""),                       // -c -f temp
            new ProcessResult(0, "table inet filter {}", ""),   // list ruleset (backup)
            new ProcessResult(1, "", "kernel rejected ruleset"),// -f config (apply)
            new ProcessResult(0, "", "")                        // -f backup (rollback)
        });
        _runner
            .Setup(r => r.RunAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => seq.Dequeue());

        var svc = CreateSvc();
        var result = await svc.ApplyConfigurationAsync();

        Assert.False(result.Success);
        Assert.Equal(1, result.ExitCode);
        Assert.NotNull(result.BackupPath);
        // Should have invoked: validate, list, apply, rollback — 4 nft calls.
        _runner.Verify(r => r.RunAsync(
            "/usr/sbin/nft",
            It.IsAny<string>(),
            It.IsAny<TimeSpan?>(),
            It.IsAny<CancellationToken>()), Times.Exactly(4));
        // No success audit when apply failed.
        _firewall.Verify(f => f.LogAuditAsync(
            "fw_system", It.IsAny<Guid>(), "APPLY_CONFIG",
            It.IsAny<object?>(), It.IsAny<object?>(), It.IsAny<string?>(),
            It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ApplyConfigurationAsync_BackupDisabled_SkipsListRulesetAndRollback()
    {
        const string config = "table inet filter {}";
        _firewall.Setup(f => f.GenerateNftablesConfigAsync(It.IsAny<CancellationToken>()))
                 .ReturnsAsync(config);
        // Sequence: validate OK, apply fails — but no backup so no rollback either.
        var seq = new Queue<ProcessResult>(new[]
        {
            new ProcessResult(0, "", ""),                       // -c -f temp
            new ProcessResult(1, "", "rejected"),               // -f config
        });
        _runner
            .Setup(r => r.RunAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(() => seq.Dequeue());

        var svc = CreateSvc(new NftApplyOptions
        {
            NftPath = "/usr/sbin/nft",
            ConfigPath = _configPath,
            BackupDirectory = _backupDir,
            CommandTimeoutSeconds = 5,
            CreateBackupBeforeApply = false
        });
        var result = await svc.ApplyConfigurationAsync();

        Assert.False(result.Success);
        Assert.Null(result.BackupPath);
        // Exactly two nft calls — no list-ruleset, no rollback.
        _runner.Verify(r => r.RunAsync(
            "/usr/sbin/nft", It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()),
            Times.Exactly(2));
    }

    [Fact]
    public async Task ApplyConfigurationAsync_GenerateThrows_IsCaughtAndReturnedAsResult()
    {
        _firewall.Setup(f => f.GenerateNftablesConfigAsync(It.IsAny<CancellationToken>()))
                 .ThrowsAsync(new InvalidOperationException("db is down"));

        var svc = CreateSvc();
        var result = await svc.ApplyConfigurationAsync();

        Assert.False(result.Success);
        Assert.Equal(-1, result.ExitCode);
        Assert.Contains("db is down", result.Error);
        _runner.VerifyNoOtherCalls();
    }
}
