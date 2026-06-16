using NetFirewall.Services.Daemon;
using NetFirewall.Services.WanMonitor;
using NetFirewall.Web.Models.Network;

namespace NetFirewall.Web.Services;

/// <inheritdoc />
public sealed class WanHealthCardBuilder : IWanHealthCardBuilder
{
    private readonly IDaemonClient _daemon;
    private readonly IWanHealthService _health;
    private readonly ILogger<WanHealthCardBuilder> _logger;

    public WanHealthCardBuilder(
        IDaemonClient daemon,
        IWanHealthService health,
        ILogger<WanHealthCardBuilder> logger)
    {
        _daemon = daemon;
        _health = health;
        _logger = logger;
    }

    public async Task<WanHealthCardViewModel> BuildAsync(WanCardOptions options, CancellationToken ct = default)
    {
        try
        {
            var env = await _daemon.GetWanHealthAsync(ct);
            var fromDaemon = env.Success && env.Data is not null;

            // Daemon unreachable/disabled → DB-direct read so the card still shows
            // health (control row + state both live in PG).
            var state   = fromDaemon ? env.Data!.State        : await _health.GetStateAsync(ct);
            var events  = fromDaemon ? env.Data!.RecentEvents : await _health.RecentEventsAsync(20, ct);
            var control = fromDaemon ? env.Data!.Control       : await _health.GetControlAsync(ct);

            // Union configured WANs with whatever has a state row, so a freshly
            // seeded WAN that hasn't been probed yet still appears.
            var configs   = await _health.GetAllConfigsAsync(ct);
            var stateById = state.ToDictionary(s => s.InterfaceId);

            var rows = configs
                .Where(c => c.Enabled)
                .OrderBy(c => c.Priority)
                .Select(c =>
                {
                    stateById.TryGetValue(c.InterfaceId, out var s);
                    return new WanHealthCardViewModel.WanHealthCardRow
                    {
                        InterfaceId          = c.InterfaceId,
                        Name                 = c.InterfaceName,
                        Role                 = s?.Role ?? string.Empty,
                        IsUp                 = s?.IsUp ?? true,
                        IsActive             = control.ActiveInterfaceId == c.InterfaceId,
                        IsPinned             = control.OverrideInterfaceId == c.InterfaceId,
                        ConsecutiveFailures  = s?.ConsecutiveFailures ?? 0,
                        ConsecutiveSuccesses = s?.ConsecutiveSuccesses ?? 0,
                        LastRttMs            = s?.LastRttMs,
                        LastTarget           = s?.LastTarget,
                        LastError            = s?.LastError,
                        LastCheckAt          = s?.LastCheckAt,
                    };
                })
                .ToList();

            // No config rows but the daemon still answered with an instant-ping
            // snapshot → render those as a fallback so the dashboard isn't empty.
            var isFallback = false;
            if (rows.Count == 0 && options.AllowPingFallback)
            {
                var ping = await _daemon.GetWanStatusAsync(ct);
                if (ping.Success && ping.Data is { Count: > 0 })
                {
                    rows = ping.Data.Select(w => new WanHealthCardViewModel.WanHealthCardRow
                    {
                        Name       = w.InterfaceName,
                        Role       = w.Role,
                        IsUp       = w.IsUp,
                        LastRttMs  = w.RttMs,
                        LastTarget = w.Target,
                        LastError  = w.Message,
                    }).ToList();
                    isFallback = true;
                }
            }

            return new WanHealthCardViewModel
            {
                Wans                  = rows,
                RecentEvents          = options.ShowEvents ? events : Array.Empty<NetFirewall.Models.WanMonitor.WanHealthEvent>(),
                ActiveInterfaceId     = control.ActiveInterfaceId,
                ActiveInterfaceName   = control.ActiveInterfaceName,
                ActiveSince           = control.ActiveSince,
                OverrideInterfaceId   = control.OverrideInterfaceId,
                OverrideInterfaceName = control.OverrideInterfaceName,
                OverrideSetBy         = control.OverrideSetBy,
                IsFallback            = isFallback,
                Options               = options,
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "WAN health card build failed");
            return new WanHealthCardViewModel { Options = options };
        }
    }
}
