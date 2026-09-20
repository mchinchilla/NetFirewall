using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics.Capture;

/// <summary>
/// Bounded packet capture: a tcpdump run that is limited by BOTH a packet count
/// and a wall-clock duration, writes one pcap under the daemon's capture
/// directory, and is downloadable until retention removes it.
///
/// Needs <c>AF_PACKET</c> in the daemon unit's <c>RestrictAddressFamilies</c> —
/// see deploy/systemd/netfirewall-daemon.service.
/// </summary>
public interface IPacketCaptureService
{
    /// <summary>Start a capture in the background; null when another invasive job holds the slot.</summary>
    Guid? Start(CaptureRequest request, string? requestedBy);

    /// <summary>Validate a BPF filter without capturing (<c>tcpdump -d</c>). Null when it compiles.</summary>
    Task<string?> ValidateFilterAsync(string filter, CancellationToken ct = default);
}

/// <summary>Where capture files live, and how they are opened and reaped.</summary>
public interface ICaptureStore
{
    /// <summary>Absolute path for a job's pcap. Creates the directory on first use.</summary>
    string PathFor(Guid jobId);

    /// <summary>Open a finished capture for download, or null when it is gone (retention, purge, never written).</summary>
    Stream? OpenRead(Guid jobId);

    bool Delete(Guid jobId);

    /// <summary>Delete captures older than <paramref name="age"/>; returns how many.</summary>
    int PurgeOlderThan(TimeSpan age);

    long TotalBytes();
}
