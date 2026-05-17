using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.Firewall;

/// <summary>Configurable knobs for <see cref="TcApplyService"/>.</summary>
public sealed class TcApplyOptions
{
    /// <summary>Where the generated script is written before bash runs it.</summary>
    public string ScriptPath { get; set; } = "/run/netfirewall/tc.sh";

    /// <summary>Path to bash on the host. Standard everywhere we deploy.</summary>
    public string BashPath { get; set; } = "/bin/bash";

    /// <summary>Hard cap so a stuck tc command can't hang the daemon forever.</summary>
    public int CommandTimeoutSeconds { get; set; } = 30;
}

[SupportedOSPlatform("linux")]
public sealed class TcApplyService : ITcApplyService
{
    private readonly IFirewallService _firewall;
    private readonly IProcessRunner _runner;
    private readonly ILogger<TcApplyService> _logger;
    private readonly TcApplyOptions _options;

    public TcApplyService(
        IFirewallService firewall,
        IProcessRunner runner,
        ILogger<TcApplyService> logger,
        IOptions<TcApplyOptions>? options = null)
    {
        _firewall = firewall;
        _runner = runner;
        _logger = logger;
        _options = options?.Value ?? new TcApplyOptions();
    }

    public async Task<NftApplyResult> ApplyAsync(CancellationToken ct = default)
    {
        try
        {
            var script = await _firewall.GenerateTcScriptAsync(ct);

            var dir = Path.GetDirectoryName(_options.ScriptPath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            await File.WriteAllTextAsync(_options.ScriptPath, script, ct);

            try { File.SetUnixFileMode(_options.ScriptPath, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute); }
            catch { /* not on a unix-y FS — fine */ }

            _logger.LogInformation("Applying tc script ({Bytes} bytes) from {Path}", script.Length, _options.ScriptPath);

            var proc = await _runner.RunAsync(
                _options.BashPath,
                _options.ScriptPath,
                TimeSpan.FromSeconds(_options.CommandTimeoutSeconds),
                ct);

            var result = new NftApplyResult
            {
                Success = proc.Success,
                ExitCode = proc.ExitCode,
                Output = proc.Output,
                Error = proc.Error,
            };

            if (proc.Success)
            {
                await _firewall.LogAuditAsync("fw_qos_config", Guid.Empty, "APPLY_TC",
                    null, new { script = _options.ScriptPath, exit = proc.ExitCode }, null, ct);
            }
            else
            {
                _logger.LogError("tc apply failed (exit {Exit}): {Err}", proc.ExitCode, proc.Error);
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "tc apply blew up before tc could even run");
            return new NftApplyResult
            {
                Success = false,
                ExitCode = -1,
                Error = ex.Message,
            };
        }
    }
}
