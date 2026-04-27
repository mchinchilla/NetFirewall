using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Processes;
using Xunit;

namespace NetFirewall.Tests.Firewall;

public class TcApplyServiceTests : IDisposable
{
    private readonly string _tempRoot;
    private readonly string _scriptPath;
    private readonly Mock<IFirewallService> _firewall = new();
    private readonly Mock<IProcessRunner> _runner = new();

    public TcApplyServiceTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), "tc-apply-tests-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempRoot);
        _scriptPath = Path.Combine(_tempRoot, "tc.sh");
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempRoot, recursive: true); } catch { /* best-effort */ }
    }

    private TcApplyService CreateSvc(TcApplyOptions? opts = null) =>
        new(
            _firewall.Object,
            _runner.Object,
            NullLogger<TcApplyService>.Instance,
            Options.Create(opts ?? new TcApplyOptions
            {
                ScriptPath = _scriptPath,
                BashPath = "/bin/bash",
                CommandTimeoutSeconds = 5
            }));

    private void StubRunner(int exitCode, string output = "", string error = "")
        => _runner
            .Setup(r => r.RunAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessResult(exitCode, output, error));

    [Fact]
    public async Task ApplyAsync_HappyPath_WritesScript_RunsBash_AndAudits()
    {
        const string script = "#!/bin/bash\ntc qdisc replace dev eth0 root htb default 30\n";
        _firewall.Setup(f => f.GenerateTcScriptAsync(It.IsAny<CancellationToken>()))
                 .ReturnsAsync(script);
        StubRunner(exitCode: 0, output: "ok");

        var svc = CreateSvc();
        var result = await svc.ApplyAsync();

        Assert.True(result.Success, result.Error);
        Assert.Equal(0, result.ExitCode);
        Assert.Equal("ok", result.Output);

        // Script was persisted before invocation.
        Assert.True(File.Exists(_scriptPath));
        Assert.Equal(script, await File.ReadAllTextAsync(_scriptPath));

        // Bash invocation matches our options.
        _runner.Verify(r => r.RunAsync(
            "/bin/bash",
            _scriptPath,
            TimeSpan.FromSeconds(5),
            It.IsAny<CancellationToken>()), Times.Once);

        // Successful apply audits to fw_qos_config.
        _firewall.Verify(f => f.LogAuditAsync(
            "fw_qos_config", Guid.Empty, "APPLY_TC",
            It.IsAny<object?>(), It.IsAny<object?>(), It.IsAny<string?>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task ApplyAsync_CreatesParentDirectoryWhenMissing()
    {
        var nested = Path.Combine(_tempRoot, "nested", "deeper", "tc.sh");
        _firewall.Setup(f => f.GenerateTcScriptAsync(It.IsAny<CancellationToken>()))
                 .ReturnsAsync("#!/bin/bash\n");
        StubRunner(exitCode: 0);

        var svc = CreateSvc(new TcApplyOptions
        {
            ScriptPath = nested,
            BashPath = "/bin/bash",
            CommandTimeoutSeconds = 5
        });
        var result = await svc.ApplyAsync();

        Assert.True(result.Success);
        Assert.True(File.Exists(nested));
    }

    [Fact]
    public async Task ApplyAsync_PropagatesBashFailure_AndDoesNotAudit()
    {
        _firewall.Setup(f => f.GenerateTcScriptAsync(It.IsAny<CancellationToken>()))
                 .ReturnsAsync("#!/bin/bash\nexit 1\n");
        StubRunner(exitCode: 1, error: "RTNETLINK answers: Operation not supported");

        var svc = CreateSvc();
        var result = await svc.ApplyAsync();

        Assert.False(result.Success);
        Assert.Equal(1, result.ExitCode);
        Assert.Contains("RTNETLINK", result.Error);
        // Script was still written so the operator can inspect it post-mortem.
        Assert.True(File.Exists(_scriptPath));
        // Audit log NOT written when apply fails.
        _firewall.Verify(f => f.LogAuditAsync(
            It.IsAny<string>(), It.IsAny<Guid>(), It.IsAny<string>(),
            It.IsAny<object?>(), It.IsAny<object?>(), It.IsAny<string?>(),
            It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task ApplyAsync_GenerateThrows_IsCaughtAndReturnedAsResult()
    {
        _firewall.Setup(f => f.GenerateTcScriptAsync(It.IsAny<CancellationToken>()))
                 .ThrowsAsync(new InvalidOperationException("missing qos config"));

        var svc = CreateSvc();
        var result = await svc.ApplyAsync();

        Assert.False(result.Success);
        Assert.Equal(-1, result.ExitCode);
        Assert.Contains("missing qos config", result.Error);
        // Bash never invoked.
        _runner.VerifyNoOtherCalls();
        // Script never written.
        Assert.False(File.Exists(_scriptPath));
    }

    [Fact]
    public async Task ApplyAsync_RunnerThrows_IsCaughtAndReturnedAsResult()
    {
        _firewall.Setup(f => f.GenerateTcScriptAsync(It.IsAny<CancellationToken>()))
                 .ReturnsAsync("#!/bin/bash\n");
        _runner
            .Setup(r => r.RunAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new TimeoutException("hung up"));

        var svc = CreateSvc();
        var result = await svc.ApplyAsync();

        Assert.False(result.Success);
        Assert.Equal(-1, result.ExitCode);
        Assert.Contains("hung up", result.Error);
    }

    [Fact]
    public async Task ApplyAsync_PassesConfiguredTimeoutToRunner()
    {
        _firewall.Setup(f => f.GenerateTcScriptAsync(It.IsAny<CancellationToken>()))
                 .ReturnsAsync("#!/bin/bash\n");
        StubRunner(exitCode: 0);

        var svc = CreateSvc(new TcApplyOptions
        {
            ScriptPath = _scriptPath,
            BashPath = "/usr/local/bin/bash",
            CommandTimeoutSeconds = 42
        });

        await svc.ApplyAsync();

        _runner.Verify(r => r.RunAsync(
            "/usr/local/bin/bash",
            _scriptPath,
            TimeSpan.FromSeconds(42),
            It.IsAny<CancellationToken>()), Times.Once);
    }
}
