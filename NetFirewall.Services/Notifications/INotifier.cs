namespace NetFirewall.Services.Notifications;

/// <summary>
/// Severity of a notification, mapped to feedback colours in the UI and to a
/// subject prefix in email.
/// </summary>
public enum NotificationLevel
{
    Info,
    Warning,
    Danger,
}

/// <summary>
/// A single notification to deliver. Channel-agnostic: each <see cref="INotifier"/>
/// renders it however suits its medium (email body, banner row, webhook JSON…).
/// </summary>
/// <param name="Source">Subsystem that raised it, e.g. "vpn".</param>
/// <param name="Level">Severity.</param>
/// <param name="DedupeKey">Stable key for the logical condition (so a UI banner
/// can upsert one row and a recovery can clear it). e.g. "vpn:&lt;server&gt;:&lt;pubkey&gt;".</param>
/// <param name="Title">Short headline.</param>
/// <param name="Body">Optional longer text.</param>
/// <param name="Resolved">True when this notifies that a previous condition
/// CLEARED (e.g. the tunnel came back). Channels use it to resolve the banner
/// alert and to phrase the email as a recovery rather than a new alarm.</param>
public sealed record NotificationMessage(
    string Source,
    NotificationLevel Level,
    string DedupeKey,
    string Title,
    string? Body,
    bool Resolved = false);

/// <summary>
/// A delivery channel for <see cref="NotificationMessage"/>. Implementations are
/// registered in DI and ALL fan out from the monitor — adding Telegram/webhook
/// later is just another registration, no change to the producer. Each notifier
/// MUST be fail-soft: a channel that's misconfigured or unreachable logs and
/// returns, it never throws into the monitor loop.
/// </summary>
public interface INotifier
{
    /// <summary>True when this channel is configured/enabled. The dispatcher skips disabled ones.</summary>
    bool IsEnabled { get; }

    Task NotifyAsync(NotificationMessage message, CancellationToken ct = default);
}
