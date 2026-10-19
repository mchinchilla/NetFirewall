namespace NetFirewall.Services.Diagnostics.SpeedTest;

/// <summary>A validated speed test, ready to run: the endpoint resolved the WAN to its mark and the source to a URL.</summary>
public sealed record SpeedTestPlan(
    string Wan,
    long Fwmark,
    string SourceName,
    Uri Url,
    int DurationSec,
    long MaxBytes,
    int Streams,
    bool KeepFile);

/// <summary>
/// WAN speed test, run as an invasive diagnostics job (it saturates the uplink
/// for everyone while it runs, so it takes the box-wide single slot).
///
/// N parallel HTTP/1.1 downloads leave through one WAN, steered by its probe
/// fwmark. Each connection re-requests the source until the duration or the byte
/// cap ends the test, so file size never caps the measurement. Throughput is
/// published once a second for the live curve; the result lands in
/// <c>diag_runs</c>. With <see cref="SpeedTestPlan.KeepFile"/> the first
/// connection's bytes are also written to disk (a faithful copy of the source,
/// or its prefix if the test ended first) and kept for download for
/// <c>SpeedTestRetentionHours</c>.
/// </summary>
public interface ISpeedTestService
{
    /// <summary>Start in the background; null when another invasive job holds the slot.</summary>
    Guid? Start(SpeedTestPlan plan, string? requestedBy);
}
