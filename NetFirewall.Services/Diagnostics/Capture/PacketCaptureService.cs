using System.Globalization;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Diagnostics.Jobs;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.Diagnostics.Capture;

public sealed partial class PacketCaptureService : IPacketCaptureService
{
    private const int PreviewLines = 200;

    private readonly IProcessRunner _runner;
    private readonly IDiagnosticJobRegistry _jobs;
    private readonly ICaptureStore _store;
    private readonly ICaptureCapabilityProbe _capability;
    private readonly DiagnosticsOptions _opts;
    private readonly ILogger<PacketCaptureService> _logger;

    public PacketCaptureService(
        IProcessRunner runner,
        IDiagnosticJobRegistry jobs,
        ICaptureStore store,
        ICaptureCapabilityProbe capability,
        IOptions<DiagnosticsOptions> opts,
        ILogger<PacketCaptureService> logger)
    {
        _runner = runner;
        _jobs = jobs;
        _store = store;
        _capability = capability;
        _opts = opts.Value;
        _logger = logger;
    }

    public Guid? Start(CaptureRequest request, string? requestedBy)
    {
        var subject = request.Interface + (string.IsNullOrWhiteSpace(request.Filter) ? "" : $" · {request.Filter}");
        var handle = _jobs.TryStart(DiagJobKind.Capture, subject, requestedBy);
        if (handle is null) return null;

        _ = Task.Run(() => RunAsync(handle, request));
        return handle.Id;
    }

    public async Task<string?> ValidateFilterAsync(string filter, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(filter)) return null;
        if (!OperatingSystem.IsLinux()) return null;

        // -d compiles the filter and prints the BPF program without touching a device.
        var res = await _runner.RunAsync(_opts.TcpdumpPath, ["-d", filter], TimeSpan.FromSeconds(5), ct);
        return res.Success ? null : FirstLine(res.Error) ?? "The filter did not compile.";
    }

    private async Task RunAsync(IDiagnosticJobHandle handle, CaptureRequest request)
    {
        using (handle)
        {
            try
            {
                if (!OperatingSystem.IsLinux())
                {
                    handle.Complete(new CaptureResult(string.Empty, 0, 0, Array.Empty<string>(), false, "Packet capture is Linux-only."));
                    return;
                }

                var duration = Math.Clamp(request.DurationSec, 5, 60);
                var packets = Math.Clamp(request.MaxPackets, 10, 2000);
                var snaplen = Math.Clamp(request.Snaplen, 64, 262144);
                var path = _store.PathFor(handle.Id);

                // `timeout --signal=INT` is what makes this bounded AND leaves a valid
                // pcap: SIGINT is tcpdump's clean stop (flush + print counters), while a
                // plain kill would truncate the file. Exit 124 = the duration elapsed,
                // which is a normal end, not an error.
                var args = new List<string>
                {
                    "--signal=INT", duration.ToString(CultureInfo.InvariantCulture),
                    _opts.TcpdumpPath,
                    "-n",                       // no DNS/service lookups (they would hang and leak queries)
                    "-Z", "root",               // do not drop privileges; we must keep writing the file
                    "-U",                       // flush every packet, so an early stop still yields a readable file
                    "-i", request.Interface,
                    "-c", packets.ToString(CultureInfo.InvariantCulture),
                    "-s", snaplen.ToString(CultureInfo.InvariantCulture),
                    "-w", path,
                };
                if (!string.IsNullOrWhiteSpace(request.Filter)) args.Add(request.Filter);

                // Hard ceiling above the internal timeout so a wedged tcpdump cannot pin the slot.
                var res = await _runner.RunAsync(_opts.TimeoutPath, args, TimeSpan.FromSeconds(duration + 15), handle.Token);

                var reachedCount = res.ExitCode == 0;      // -c satisfied
                var timedOut = res.ExitCode == 124;        // duration elapsed
                if (!reachedCount && !timedOut)
                {
                    var why = Explain(FirstLine(res.Error) ?? $"tcpdump exited with {res.ExitCode}",
                                      request.Interface, _capability.Probe());
                    _store.Delete(handle.Id);
                    // No pcap, no packets — a failure, not a green "completed" panel.
                    handle.Fail(why);
                    return;
                }

                var size = File.Exists(path) ? new FileInfo(path).Length : 0;
                var captured = ParseCapturedCount(res.Error) ?? 0;
                handle.Progress(captured);

                var preview = size > 0 ? await PreviewAsync(path, handle.Token) : Array.Empty<string>();
                handle.Complete(new CaptureResult(
                    FileName: $"netfirewall-{request.Interface}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.pcap",
                    SizeBytes: size,
                    PacketsCaptured: captured,
                    Preview: preview,
                    ReachedLimit: reachedCount));
            }
            catch (OperationCanceledException)
            {
                // Cancelled by the operator: tcpdump already got SIGINT via the token,
                // so whatever it wrote is a valid pcap.
                var path = _store.PathFor(handle.Id);
                var size = File.Exists(path) ? new FileInfo(path).Length : 0;
                handle.Complete(new CaptureResult($"netfirewall-{request.Interface}-partial.pcap", size, 0, Array.Empty<string>(), false,
                    size > 0 ? null : "Cancelled before any packet was written."));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Packet capture job {Id} failed", handle.Id);
                _store.Delete(handle.Id);
                handle.Complete(new CaptureResult(string.Empty, 0, 0, Array.Empty<string>(), false, ex.Message));
            }
        }
    }

    private async Task<IReadOnlyList<string>> PreviewAsync(string path, CancellationToken ct)
    {
        try
        {
            var res = await _runner.RunAsync(_opts.TcpdumpPath,
                ["-n", "-r", path, "-c", PreviewLines.ToString(CultureInfo.InvariantCulture)],
                TimeSpan.FromSeconds(10), ct);
            return res.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(l => l.TrimEnd()).ToList();
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not build a preview for {Path}", path);
            return Array.Empty<string>();
        }
    }

    /// <summary>tcpdump reports "N packets captured" on stderr when it stops.</summary>
    internal static int? ParseCapturedCount(string? stderr)
    {
        var m = CapturedRx().Match(stderr ?? string.Empty);
        return m.Success && int.TryParse(m.Groups[1].Value, out var n) ? n : null;
    }

    /// <summary>
    /// Replace tcpdump's least helpful error with what the probe actually found.
    ///
    /// libpcap says "Packet capture is not supported on that device" for several
    /// unrelated reasons, and by naming the device it points the operator at the
    /// NIC. Asking the kernel ourselves says which one it is, so the panel states a
    /// fact instead of listing suspects.
    /// </summary>
    internal static string Explain(string message, string iface, CapturePreflight probe)
    {
        var deviceRefused = message.Contains("not supported on that device", StringComparison.OrdinalIgnoreCase)
                            || message.Contains("You don't have permission", StringComparison.OrdinalIgnoreCase)
                            || message.Contains("Operation not permitted", StringComparison.OrdinalIgnoreCase);
        if (!deviceRefused) return message;

        return probe.Status switch
        {
            CaptureCapability.BlockedBySandbox =>
                $"{message} — this is not the NIC. The daemon may not open capture sockets at all "
                + $"({probe.Detail}): add AF_PACKET to RestrictAddressFamilies in "
                + "netfirewall-daemon.service, then `systemctl daemon-reload && systemctl restart "
                + "netfirewall-daemon`. Re-running deploy/install.sh installs the current unit.",

            CaptureCapability.PermissionDenied =>
                $"{message} — the daemon may not open capture sockets ({probe.Detail}). "
                + "It needs CAP_NET_RAW; check CapabilityBoundingSet in netfirewall-daemon.service.",

            // The sandbox is fine, so the device really is the problem.
            CaptureCapability.Available =>
                $"{message} — the daemon CAN open capture sockets ({probe.Detail}), so the refusal is "
                + $"about {iface} itself: check that it exists, is up, and is a type tcpdump can read "
                + $"(`ip -br link show {iface}`).",

            _ => $"{message} — could not determine whether the daemon may open capture sockets "
                 + $"({probe.Detail}).",
        };
    }

    private static string? FirstLine(string? s) =>
        string.IsNullOrWhiteSpace(s) ? null : s.Split('\n', StringSplitOptions.RemoveEmptyEntries)[0].Trim();

    [GeneratedRegex(@"(\d+) packets? captured")]
    private static partial Regex CapturedRx();
}
