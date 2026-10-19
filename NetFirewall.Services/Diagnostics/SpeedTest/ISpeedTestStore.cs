using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics.SpeedTest;

/// <summary>
/// Kept speed-test payloads. Each one is two files under
/// <see cref="DiagnosticsOptions.SpeedTestDirectory"/>, both named by the job GUID
/// so a request can never name a path: <c>{id}.bin</c> (the payload) and
/// <c>{id}.json</c> (its <see cref="SpeedTestFile"/>, which carries the expiry).
/// While the test runs the payload is <c>{id}.part</c>; only a committed file is
/// listed or served. The metadata lives beside the file rather than in the
/// database so the two can never disagree and no migration has to land first.
/// </summary>
public interface ISpeedTestStore
{
    /// <summary>Path the running test writes to. Creates the directory on first use.</summary>
    string PartPathFor(Guid id);

    /// <summary>Promote <c>{id}.part</c> to a downloadable file and write its metadata.</summary>
    Task CommitAsync(SpeedTestFile meta, CancellationToken ct = default);

    /// <summary>Remove an uncommitted payload (failed or empty test).</summary>
    void Discard(Guid id);

    /// <summary>Committed, unexpired files, newest first.</summary>
    Task<IReadOnlyList<SpeedTestFile>> ListAsync(CancellationToken ct = default);

    /// <summary>Null when the file is gone OR past its expiry — an expired link is dead even before the sweeper runs.</summary>
    Task<SpeedTestFile?> GetAsync(Guid id, CancellationToken ct = default);

    /// <summary>Open an unexpired payload for streaming, or null.</summary>
    Task<(SpeedTestFile Meta, Stream Content)?> OpenReadAsync(Guid id, CancellationToken ct = default);

    bool Delete(Guid id);

    /// <summary>
    /// Delete expired files, and payload/metadata halves that lost their partner.
    /// <paramref name="includeInProgress"/> also removes <c>.part</c> files — only
    /// safe at startup, when no test can be running.
    /// </summary>
    Task<int> SweepAsync(bool includeInProgress, CancellationToken ct = default);

    /// <summary>
    /// Why a kept file of up to <paramref name="bytes"/> cannot be accepted now
    /// (quota or free space), or null when it can.
    /// </summary>
    string? CheckCapacity(long bytes);
}
