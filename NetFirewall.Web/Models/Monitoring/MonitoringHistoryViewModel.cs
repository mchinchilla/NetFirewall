namespace NetFirewall.Web.Models.Monitoring;

/// <summary>
/// Pre-baked chart series for the History tab. Arrays are aligned by index
/// against <see cref="Labels"/>; Chart.js consumes them via JsonSerializer.
/// </summary>
public sealed class MonitoringHistoryViewModel
{
    public required string Range { get; set; }
    public DateTime From { get; set; }
    public DateTime To { get; set; }
    public int SampleCount { get; set; }

    public string[] Labels      { get; set; } = [];
    public double[] CpuSeries   { get; set; } = [];
    public double[] MemorySeries { get; set; } = [];
    public double[] LoadSeries  { get; set; } = [];
    public double[] RxSeries    { get; set; } = [];
    public double[] TxSeries    { get; set; } = [];
}
