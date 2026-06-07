using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Processes;
using NetFirewall.Services.Vpn;
using NetFirewall.Tests.Infra;
using Xunit;

namespace NetFirewall.Tests.Vpn;

/// <summary>
/// Mock-IProcessRunner coverage of <see cref="WireGuardApplyService"/>.
/// Verifies key generation parsing, the apply script's hot-reload-vs-cold-up
/// branch, and exception swallowing on file/runner errors.
/// </summary>
// WireGuardApplyService is [SupportedOSPlatform("linux")]; [LinuxOnlyFact] skips
// these off Linux. This class attribute keeps CA1416 quiet on the call sites.
[System.Runtime.Versioning.SupportedOSPlatform("linux")]
public class WireGuardApplyServiceTests : IDisposable
{
    private readonly string _tempDir;
    private readonly Mock<IWireGuardConfigService> _config = new();
    private readonly Mock<IProcessRunner> _runner = new();

    public WireGuardApplyServiceTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), "wg-tests-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try { Directory.Delete(_tempDir, recursive: true); } catch { /* best effort */ }
    }

    private WireGuardApplyService CreateSvc() =>
        new(_config.Object, _runner.Object, NullLogger<WireGuardApplyService>.Instance,
            Options.Create(new WireGuardApplyOptions
            {
                ConfigDir = _tempDir,
                BashPath = "/bin/bash",
                CommandTimeoutSeconds = 5
            }));

    private static WgServer Server(string name = "wg0") => new()
    {
        Id = Guid.NewGuid(),
        Name = name,
        PrivateKey = "PRIV", PublicKey = "PUB",
        ListenPort = 51820, AddressCidr = "10.10.0.1/24",
        Enabled = true
    };

    // ── GenerateKeyPair ────────────────────────────────────────────────

    [LinuxOnlyFact]
    public async Task GenerateKeyPairAsync_ParsesTwoLineOutputIntoTuple()
    {
        _runner.Setup(r => r.RunAsync("/bin/bash", It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessResult(0, "PRIV_KEY_BASE64\nPUB_KEY_BASE64\n", ""));

        var (priv, pub) = await CreateSvc().GenerateKeyPairAsync();

        Assert.Equal("PRIV_KEY_BASE64", priv);
        Assert.Equal("PUB_KEY_BASE64", pub);
    }

    [LinuxOnlyFact]
    public async Task GenerateKeyPairAsync_NonZeroExit_Throws()
    {
        _runner.Setup(r => r.RunAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessResult(1, "", "wg not found"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => CreateSvc().GenerateKeyPairAsync());
    }

    [LinuxOnlyFact]
    public async Task GenerateKeyPairAsync_LessThanTwoLines_Throws()
    {
        _runner.Setup(r => r.RunAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessResult(0, "OnlyOneLine\n", ""));

        await Assert.ThrowsAsync<InvalidOperationException>(() => CreateSvc().GenerateKeyPairAsync());
    }

    // ── GeneratePresharedKey ───────────────────────────────────────────

    [LinuxOnlyFact]
    public async Task GeneratePresharedKeyAsync_TrimsTrailingNewlineFromOutput()
    {
        _runner.Setup(r => r.RunAsync("wg", "genpsk", It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessResult(0, "PSK_BASE64\n", ""));

        var psk = await CreateSvc().GeneratePresharedKeyAsync();

        Assert.Equal("PSK_BASE64", psk); // newline trimmed
    }

    [LinuxOnlyFact]
    public async Task GeneratePresharedKeyAsync_NonZeroExit_Throws()
    {
        _runner.Setup(r => r.RunAsync("wg", "genpsk", It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessResult(1, "", "wg missing"));

        await Assert.ThrowsAsync<InvalidOperationException>(() => CreateSvc().GeneratePresharedKeyAsync());
    }

    // ── ApplyAsync ─────────────────────────────────────────────────────

    [LinuxOnlyFact]
    public async Task ApplyAsync_HappyPath_WritesConfig_AndRunsBash_AndReturnsSuccess()
    {
        _config.Setup(c => c.GenerateServerConfig(It.IsAny<WgServer>(), It.IsAny<IReadOnlyList<WgPeer>>()))
            .Returns("[Interface]\nPrivateKey = PRIV\n");
        _runner.Setup(r => r.RunAsync("/bin/bash", It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessResult(0, "ok", ""));

        var server = Server();
        var result = await CreateSvc().ApplyAsync(server, Array.Empty<WgPeer>());

        Assert.True(result.Success);

        // Config landed at /<tempdir>/wg0.conf with the expected contents.
        var path = Path.Combine(_tempDir, "wg0.conf");
        Assert.True(File.Exists(path));
        var written = await File.ReadAllTextAsync(path);
        Assert.Contains("[Interface]", written);

        // Bash invoked with a script that branches between syncconf/up.
        _runner.Verify(r => r.RunAsync(
            "/bin/bash",
            It.Is<string>(args => args.Contains("wg syncconf") && args.Contains("wg-quick up")),
            It.IsAny<TimeSpan?>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [LinuxOnlyFact]
    public async Task ApplyAsync_BashFails_ResultCarriesExitCodeAndErrorOutput()
    {
        _config.Setup(c => c.GenerateServerConfig(It.IsAny<WgServer>(), It.IsAny<IReadOnlyList<WgPeer>>()))
            .Returns("[Interface]\n");
        _runner.Setup(r => r.RunAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessResult(1, "", "interface already exists"));

        var result = await CreateSvc().ApplyAsync(Server(), Array.Empty<WgPeer>());

        Assert.False(result.Success);
        Assert.Equal(1, result.ExitCode);
        Assert.Contains("interface already exists", result.Error);
    }

    [LinuxOnlyFact]
    public async Task ApplyAsync_RunnerThrows_CaughtAndReturnedAsResult()
    {
        _config.Setup(c => c.GenerateServerConfig(It.IsAny<WgServer>(), It.IsAny<IReadOnlyList<WgPeer>>()))
            .Returns("[Interface]\n");
        _runner.Setup(r => r.RunAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("kapow"));

        var result = await CreateSvc().ApplyAsync(Server(), Array.Empty<WgPeer>());

        Assert.False(result.Success);
        Assert.Equal(-1, result.ExitCode);
        Assert.Contains("kapow", result.Error);
    }

    // ── StopAsync ──────────────────────────────────────────────────────

    [LinuxOnlyFact]
    public async Task StopAsync_RunsWgQuickDown_AndPropagatesResult()
    {
        _runner.Setup(r => r.RunAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<TimeSpan?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new ProcessResult(0, "interface down", ""));

        var result = await CreateSvc().StopAsync("wg0");

        Assert.True(result.Success);
        Assert.Equal("interface down", result.Output);
    }
}
