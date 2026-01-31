namespace NetFirewall.Services.Firewall;

/// <summary>
/// Service for applying nftables configuration to the system.
/// </summary>
public interface INftApplyService
{
    /// <summary>
    /// Apply the current firewall configuration from database.
    /// </summary>
    Task<NftApplyResult> ApplyConfigurationAsync(CancellationToken ct = default);

    /// <summary>
    /// Validate nftables configuration without applying.
    /// </summary>
    Task<NftApplyResult> ValidateConfigurationAsync(string config, CancellationToken ct = default);

    /// <summary>
    /// Apply configuration from a specific file.
    /// </summary>
    Task<NftApplyResult> ApplyFromFileAsync(string filePath, CancellationToken ct = default);

    /// <summary>
    /// Get the current nftables ruleset from the system.
    /// </summary>
    Task<string> GetCurrentRulesetAsync(CancellationToken ct = default);

    /// <summary>
    /// Backup current ruleset before applying changes.
    /// </summary>
    Task<string> BackupCurrentRulesetAsync(CancellationToken ct = default);

    /// <summary>
    /// Restore ruleset from a backup file.
    /// </summary>
    Task<NftApplyResult> RestoreFromBackupAsync(string backupPath, CancellationToken ct = default);
}

/// <summary>
/// Result of nftables apply operation.
/// </summary>
public class NftApplyResult
{
    public bool Success { get; set; }
    public string? Output { get; set; }
    public string? Error { get; set; }
    public int ExitCode { get; set; }
    public DateTime AppliedAt { get; set; } = DateTime.UtcNow;
    public string? BackupPath { get; set; }
}
