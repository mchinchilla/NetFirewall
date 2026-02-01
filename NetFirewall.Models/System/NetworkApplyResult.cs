namespace NetFirewall.Models.System;

public class NetworkApplyResult
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
    public string? Output { get; set; }
    public string? ErrorOutput { get; set; }
    public int ExitCode { get; set; }
    public string? ConfigFilePath { get; set; }
    public string? BackupFilePath { get; set; }
}
