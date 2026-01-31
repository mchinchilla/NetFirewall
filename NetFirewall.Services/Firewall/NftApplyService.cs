using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NetFirewall.Services.Firewall;

/// <summary>
/// Configuration options for NftApplyService.
/// </summary>
public class NftApplyOptions
{
    public string NftPath { get; set; } = "/usr/sbin/nft";
    public string ConfigPath { get; set; } = "/etc/nftables.conf";
    public string BackupDirectory { get; set; } = "/var/lib/netfirewall/backups";
    public int CommandTimeoutSeconds { get; set; } = 30;
    public bool CreateBackupBeforeApply { get; set; } = true;
}

/// <summary>
/// Service for applying nftables configuration to Linux systems.
/// Executes nft commands with proper error handling and backup support.
/// </summary>
public sealed class NftApplyService : INftApplyService
{
    private readonly IFirewallService _firewallService;
    private readonly ILogger<NftApplyService> _logger;
    private readonly NftApplyOptions _options;

    public NftApplyService(
        IFirewallService firewallService,
        ILogger<NftApplyService> logger,
        IOptions<NftApplyOptions>? options = null)
    {
        _firewallService = firewallService;
        _logger = logger;
        _options = options?.Value ?? new NftApplyOptions();
    }

    public async Task<NftApplyResult> ApplyConfigurationAsync(CancellationToken ct = default)
    {
        try
        {
            // Generate configuration from database
            var config = await _firewallService.GenerateNftablesConfigAsync(ct);

            // Validate first
            var validation = await ValidateConfigurationAsync(config, ct);
            if (!validation.Success)
            {
                _logger.LogError("Configuration validation failed: {Error}", validation.Error);
                return validation;
            }

            // Create backup if enabled
            string? backupPath = null;
            if (_options.CreateBackupBeforeApply)
            {
                backupPath = await BackupCurrentRulesetAsync(ct);
                _logger.LogInformation("Created backup at {BackupPath}", backupPath);
            }

            // Write configuration to file
            await File.WriteAllTextAsync(_options.ConfigPath, config, ct);
            _logger.LogDebug("Wrote configuration to {Path}", _options.ConfigPath);

            // Apply configuration
            var result = await ApplyFromFileAsync(_options.ConfigPath, ct);
            result.BackupPath = backupPath;

            if (result.Success)
            {
                await _firewallService.LogAuditAsync(
                    "fw_system",
                    Guid.Empty,
                    "APPLY_CONFIG",
                    null,
                    new { ConfigPath = _options.ConfigPath, BackupPath = backupPath },
                    null,
                    ct);

                _logger.LogInformation("Successfully applied firewall configuration");
            }
            else
            {
                _logger.LogError("Failed to apply configuration: {Error}", result.Error);

                // Attempt rollback if we have a backup
                if (backupPath != null)
                {
                    _logger.LogWarning("Attempting rollback from backup {BackupPath}", backupPath);
                    var rollback = await RestoreFromBackupAsync(backupPath, ct);
                    if (rollback.Success)
                    {
                        _logger.LogInformation("Rollback successful");
                    }
                    else
                    {
                        _logger.LogError("Rollback failed: {Error}", rollback.Error);
                    }
                }
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error applying configuration");
            return new NftApplyResult
            {
                Success = false,
                Error = ex.Message,
                ExitCode = -1
            };
        }
    }

    public async Task<NftApplyResult> ValidateConfigurationAsync(string config, CancellationToken ct = default)
    {
        // Write to temporary file
        var tempFile = Path.Combine(Path.GetTempPath(), $"nft-validate-{Guid.NewGuid()}.conf");

        try
        {
            await File.WriteAllTextAsync(tempFile, config, ct);

            // nft -c -f checks syntax without applying
            var result = await ExecuteNftCommandAsync($"-c -f {tempFile}", ct);

            return result;
        }
        finally
        {
            if (File.Exists(tempFile))
            {
                File.Delete(tempFile);
            }
        }
    }

    public async Task<NftApplyResult> ApplyFromFileAsync(string filePath, CancellationToken ct = default)
    {
        if (!File.Exists(filePath))
        {
            return new NftApplyResult
            {
                Success = false,
                Error = $"Configuration file not found: {filePath}",
                ExitCode = -1
            };
        }

        return await ExecuteNftCommandAsync($"-f {filePath}", ct);
    }

    public async Task<string> GetCurrentRulesetAsync(CancellationToken ct = default)
    {
        var result = await ExecuteNftCommandAsync("list ruleset", ct);
        return result.Success ? result.Output ?? "" : $"# Error: {result.Error}";
    }

    public async Task<string> BackupCurrentRulesetAsync(CancellationToken ct = default)
    {
        // Ensure backup directory exists
        Directory.CreateDirectory(_options.BackupDirectory);

        // Get current ruleset
        var ruleset = await GetCurrentRulesetAsync(ct);

        // Generate backup filename with timestamp
        var timestamp = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss");
        var backupPath = Path.Combine(_options.BackupDirectory, $"nftables-{timestamp}.conf");

        await File.WriteAllTextAsync(backupPath, ruleset, ct);

        _logger.LogDebug("Backed up ruleset to {Path}", backupPath);

        return backupPath;
    }

    public async Task<NftApplyResult> RestoreFromBackupAsync(string backupPath, CancellationToken ct = default)
    {
        if (!File.Exists(backupPath))
        {
            return new NftApplyResult
            {
                Success = false,
                Error = $"Backup file not found: {backupPath}",
                ExitCode = -1
            };
        }

        _logger.LogInformation("Restoring from backup: {Path}", backupPath);

        return await ApplyFromFileAsync(backupPath, ct);
    }

    private async Task<NftApplyResult> ExecuteNftCommandAsync(string arguments, CancellationToken ct)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = _options.NftPath,
            Arguments = arguments,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        try
        {
            using var process = new Process { StartInfo = startInfo };

            process.Start();

            var outputTask = process.StandardOutput.ReadToEndAsync(ct);
            var errorTask = process.StandardError.ReadToEndAsync(ct);

            var timeoutTask = Task.Delay(TimeSpan.FromSeconds(_options.CommandTimeoutSeconds), ct);
            var processTask = process.WaitForExitAsync(ct);

            var completedTask = await Task.WhenAny(processTask, timeoutTask);

            if (completedTask == timeoutTask)
            {
                try { process.Kill(); } catch { /* ignore */ }
                return new NftApplyResult
                {
                    Success = false,
                    Error = $"Command timed out after {_options.CommandTimeoutSeconds} seconds",
                    ExitCode = -1
                };
            }

            var output = await outputTask;
            var error = await errorTask;

            return new NftApplyResult
            {
                Success = process.ExitCode == 0,
                Output = output,
                Error = string.IsNullOrEmpty(error) ? null : error,
                ExitCode = process.ExitCode
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to execute nft command: {Args}", arguments);
            return new NftApplyResult
            {
                Success = false,
                Error = ex.Message,
                ExitCode = -1
            };
        }
    }
}
