namespace NetFirewall.Services.Monitoring;

/// <summary>
/// Reports the state of systemd units that operationally matter for NetFirewall
/// (daemon, web, dhcp, wanmonitor, postgres). Wraps <c>systemctl is-active</c>
/// + <c>systemctl show</c> via the injected process runner. Linux-only.
/// </summary>
public interface ISystemServiceHealthService
{
    Task<IReadOnlyList<ServiceHealth>> GetAllAsync(CancellationToken ct = default);
}

/// <summary>
/// Snapshot of one systemd unit. <c>ActiveState</c> is the raw systemctl value
/// (active, inactive, failed, activating, deactivating). <c>SubState</c> adds
/// detail (running, dead, exited). <c>Enabled</c> = unit-file is enabled.
/// <c>SinceUtc</c> = last state transition timestamp.
/// </summary>
public sealed record ServiceHealth(
    string UnitName,
    string DisplayName,
    string ActiveState,
    string? SubState,
    bool Enabled,
    DateTime? SinceUtc,
    string? StatusText);
