using Microsoft.Extensions.Logging;

namespace NetFirewall.Services.Notifications;

/// <summary>
/// Fans a single <see cref="NotificationMessage"/> out to every enabled
/// <see cref="INotifier"/>. The monitor depends on this one interface instead of
/// the channel list, so wiring a new channel never touches the producer. Fully
/// fail-soft: each channel is awaited independently and its failure is logged,
/// never propagated.
/// </summary>
public interface INotificationDispatcher
{
    Task DispatchAsync(NotificationMessage message, CancellationToken ct = default);
}

public sealed class NotificationDispatcher : INotificationDispatcher
{
    private readonly IEnumerable<INotifier> _notifiers;
    private readonly ILogger<NotificationDispatcher> _logger;

    public NotificationDispatcher(IEnumerable<INotifier> notifiers, ILogger<NotificationDispatcher> logger)
    {
        _notifiers = notifiers;
        _logger = logger;
    }

    public async Task DispatchAsync(NotificationMessage message, CancellationToken ct = default)
    {
        var enabled = _notifiers.Where(n => n.IsEnabled).ToArray();
        if (enabled.Length == 0)
        {
            _logger.LogDebug("No enabled notifiers — dropping notification {Key}", message.DedupeKey);
            return;
        }

        // Each channel is isolated: one throwing/timing-out must not stop the
        // others or bubble into the monitor loop.
        var tasks = enabled.Select(async n =>
        {
            try
            {
                await n.NotifyAsync(message, ct);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Notifier {Notifier} failed for {Key}",
                    n.GetType().Name, message.DedupeKey);
            }
        });
        await Task.WhenAll(tasks);
    }
}
