using Microsoft.Extensions.Logging;
using NetFirewall.Models;
using NetFirewall.Models.Wol;
using NetFirewall.Services.Daemon;

namespace NetFirewall.Services.Wol;

public sealed class WolDeviceWakeService : IWolDeviceWakeService
{
    /// <summary>
    /// Wakes in flight at once. Each is a daemon round trip of ~250 ms (three copies,
    /// 100 ms apart), so a few in parallel keeps "Wake all" quick without a burst of
    /// requests against the daemon socket.
    /// </summary>
    private const int Parallelism = 4;

    private readonly IWolDeviceService _devices;
    private readonly IDaemonClient _daemon;
    private readonly ILogger<WolDeviceWakeService> _logger;

    public WolDeviceWakeService(IWolDeviceService devices, IDaemonClient daemon, ILogger<WolDeviceWakeService> logger)
    {
        _devices = devices;
        _daemon = daemon;
        _logger = logger;
    }

    public async Task<ServiceResponse<WolWakeResult>> WakeAsync(Guid deviceId, string? by, CancellationToken ct = default)
    {
        var device = await _devices.GetByIdAsync(deviceId, ct);
        if (device is null) return ServiceResponse<WolWakeResult>.Fail("Device not found.");

        var sent = await SendAsync(device, by, ct);
        return sent.Success
            ? ServiceResponse<WolWakeResult>.Ok(sent.Data!,
                $"Wake sent to {device.Name} on {sent.Data!.Interface}. It usually takes 10-60 s to show up as online.")
            : sent;
    }

    public async Task<ServiceResponse<WolBatchResult>> WakeManyAsync(IReadOnlyCollection<Guid>? deviceIds, string? by, CancellationToken ct = default)
    {
        var selection = deviceIds is { Count: > 0 };
        var devices = await _devices.GetAllAsync(ct);
        if (selection)
        {
            var wanted = deviceIds!.ToHashSet();
            devices = devices.Where(d => wanted.Contains(d.Id)).ToList();
            if (devices.Count == 0)
                return ServiceResponse<WolBatchResult>.Fail("None of the selected devices exist any more. Reload the list.");
        }
        else if (devices.Count == 0)
        {
            return ServiceResponse<WolBatchResult>.Fail("No saved devices to wake.");
        }

        var items = new WolBatchItem[devices.Count];
        await Parallel.ForEachAsync(Enumerable.Range(0, devices.Count),
            new ParallelOptions { MaxDegreeOfParallelism = Parallelism, CancellationToken = ct },
            async (i, token) =>
            {
                var d = devices[i];
                var sent = await SendAsync(d, by, token);
                items[i] = new WolBatchItem(d.Id, d.Name, sent.Success, sent.Data?.Interface,
                    sent.Success ? null : sent.Message ?? "Wake failed.");
            });

        var result = new WolBatchResult(items);
        _logger.LogInformation("Wake-on-LAN {Scope}: {Sent}/{Total} sent by {By}",
            selection ? "selection" : "all", result.Sent, result.Total, by);
        return Summarise(result, selection);
    }

    /// <summary>One daemon call; the timestamp is only written for a packet that actually left.</summary>
    private async Task<ServiceResponse<WolWakeResult>> SendAsync(WolDevice d, string? by, CancellationToken ct)
    {
        var sent = await _daemon.WakeOnLanAsync(new WolWakeRequest(d.MacAddress, d.Interface, null, d.Port), ct);
        if (!sent.Success) return sent;

        try
        {
            await _devices.MarkWokenAsync(d.Id, by, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // The packet is on the wire; a missed "last woken" stamp is not a failed wake.
            _logger.LogWarning(ex, "Wake-on-LAN: sent to {Name} but could not record it", d.Name);
        }
        return sent;
    }

    /// <summary>
    /// All sent → success. None sent → error (one reason when they all share it —
    /// "daemon unreachable" repeated per device says nothing new). Some sent →
    /// failure WITH per-device Errors, which the toast renders as a warning.
    /// </summary>
    internal static ServiceResponse<WolBatchResult> Summarise(WolBatchResult result, bool selection)
    {
        var failed = result.Items.Where(i => !i.Sent).ToList();
        if (failed.Count == 0)
            return ServiceResponse<WolBatchResult>.Ok(result, result.Total == 1
                ? $"Wake sent to {result.Items[0].Name}."
                : (selection ? $"Wake sent to the {result.Total} selected devices." : $"Wake sent to all {result.Total} devices.")
                  + " They usually show up as online within a minute.");

        var reasons = failed.Select(f => f.Error).Distinct().ToList();
        var listed = string.Join("; ", failed.Take(3).Select(f => $"{f.Name}: {f.Error}"))
                     + (failed.Count > 3 ? $"; and {failed.Count - 3} more." : string.Empty);

        if (result.Sent == 0)
            return new ServiceResponse<WolBatchResult>
            {
                Success = false,
                Data = result,
                Message = reasons.Count == 1 && failed.Count > 1
                    ? $"No wake was sent: {reasons[0]}"
                    : $"No wake was sent. {listed}",
            };

        return new ServiceResponse<WolBatchResult>
        {
            Success = false,
            Data = result,
            Message = $"Wake sent to {result.Sent} of {result.Total} devices. Failed: {listed}",
            Errors = failed.GroupBy(f => f.Name)
                .ToDictionary(g => g.Key, g => g.Select(f => f.Error ?? "Wake failed.").ToArray()),
        };
    }
}
