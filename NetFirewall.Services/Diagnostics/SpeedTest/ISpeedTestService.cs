namespace NetFirewall.Services.Diagnostics.SpeedTest;

/// <summary>
/// A validated speed test, ready to run: the endpoint resolved the WAN to its mark and
/// the source to a URL. <see cref="DurationSec"/> is the whole budget — seconds for a
/// burst, the time limit for a full download. <see cref="MaxBytes"/> is the byte cap of
/// a burst, and the largest file a full download will take on.
/// </summary>
public sealed record SpeedTestPlan(
    string Wan,
    long Fwmark,
    string SourceName,
    Uri Url,
    int DurationSec,
    long MaxBytes,
    int Streams,
    bool KeepFile,
    NetFirewall.Models.Diagnostics.SpeedTestMode Mode = NetFirewall.Models.Diagnostics.SpeedTestMode.Burst);

/// <summary>
/// WAN speed test, run as an invasive diagnostics job (it saturates the uplink
/// for everyone while it runs, so it takes the box-wide single slot).
///
/// N parallel HTTP/1.1 connections leave through one WAN, steered by its probe
/// fwmark. Throughput is published once a second for the live curve; the result
/// lands in <c>diag_runs</c>. Two modes:
///
/// <list type="bullet">
/// <item><b>Burst</b> — each connection re-requests the source until the seconds or
/// the byte cap end the test, so file size never caps the measurement. With
/// <see cref="SpeedTestPlan.KeepFile"/> the first connection's bytes are kept (a
/// faithful copy of the source, or its prefix).</item>
/// <item><b>Full download</b> — the source is fetched once, to the last byte, split
/// into HTTP Range chunks the connections pull from a queue; a dropped connection
/// resumes its chunk. Ends when the file is whole or the time limit (minutes) hits.
/// Reports the slowest second, stall seconds and reconnects — the provider's
/// endurance. A kept file is written in place at each chunk's offset and kept only
/// when complete.</item>
/// </list>
///
/// Kept files stay downloadable for <c>SpeedTestRetentionHours</c>.
/// </summary>
public interface ISpeedTestService
{
    /// <summary>Start in the background; null when another invasive job holds the slot.</summary>
    Guid? Start(SpeedTestPlan plan, string? requestedBy);
}
