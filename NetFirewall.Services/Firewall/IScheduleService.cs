using NetFirewall.Models.Firewall;

namespace NetFirewall.Services.Firewall;

/// <summary>
/// CRUD over <c>fw_schedules</c>. Schedules attach to filter rules via
/// <see cref="FwFilterRule.ScheduleId"/>. The watcher service in the daemon
/// triggers nft re-apply at start, at each Start/End, and on schedule writes.
/// </summary>
public interface IScheduleService
{
    Task<IReadOnlyList<FwSchedule>> GetAllAsync(CancellationToken ct = default);
    Task<FwSchedule?> GetByIdAsync(Guid id, CancellationToken ct = default);
    Task<FwSchedule> CreateAsync(FwSchedule s, CancellationToken ct = default);
    Task<FwSchedule> UpdateAsync(FwSchedule s, CancellationToken ct = default);
    Task<bool> DeleteAsync(Guid id, CancellationToken ct = default);
}
