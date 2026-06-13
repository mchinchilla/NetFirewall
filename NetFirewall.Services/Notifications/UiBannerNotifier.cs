using Microsoft.Extensions.Logging;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Vpn;

namespace NetFirewall.Services.Notifications;

/// <summary>
/// Persists notifications into the <c>system_alerts</c> store so the Web's
/// notification banner can surface them. A non-resolved message raises (upserts)
/// an active alert; a resolved message clears it. Always enabled — it has no
/// external dependency, it's just a DB write the UI polls.
/// </summary>
public sealed class UiBannerNotifier : INotifier
{
    private readonly IVpnHealthService _health;
    private readonly ILogger<UiBannerNotifier> _logger;

    public UiBannerNotifier(IVpnHealthService health, ILogger<UiBannerNotifier> logger)
    {
        _health = health;
        _logger = logger;
    }

    public bool IsEnabled => true;

    public async Task NotifyAsync(NotificationMessage message, CancellationToken ct = default)
    {
        if (message.Resolved)
        {
            await _health.ResolveAlertAsync(message.DedupeKey, ct);
            _logger.LogDebug("Resolved UI alert {Key}", message.DedupeKey);
            return;
        }

        await _health.RaiseAlertAsync(new SystemAlert
        {
            Source    = message.Source,
            Severity  = message.Level switch
            {
                NotificationLevel.Danger  => "danger",
                NotificationLevel.Warning => "warning",
                _                         => "info",
            },
            DedupeKey = message.DedupeKey,
            Title     = message.Title,
            Body      = message.Body,
        }, ct);
        _logger.LogDebug("Raised UI alert {Key}", message.DedupeKey);
    }
}
