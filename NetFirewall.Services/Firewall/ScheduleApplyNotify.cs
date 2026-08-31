using Microsoft.Extensions.Logging;
using Npgsql;

namespace NetFirewall.Services.Firewall;

/// <summary>
/// Postgres NOTIFY so the daemon's <see cref="ScheduleWatcherService"/>
/// wakes the moment a schedule or a scheduled filter rule is written,
/// instead of waiting for the next clock edge. Fail-soft: a notify miss
/// only delays apply until <see cref="ScheduleApplyPlanner.MaxTick"/>.
/// </summary>
internal static class ScheduleApplyNotify
{
    public const string Channel = "fw_schedule_apply";

    public static async Task TrySendAsync(
        NpgsqlConnection conn,
        string reason,
        ILogger logger,
        CancellationToken ct)
    {
        try
        {
            await using var cmd = new NpgsqlCommand("SELECT pg_notify(@channel, @payload)", conn);
            cmd.Parameters.AddWithValue("channel", Channel);
            cmd.Parameters.AddWithValue("payload", reason);
            await cmd.ExecuteNonQueryAsync(ct);
        }
        catch (Exception ex)
        {
            logger.LogDebug(ex, "pg_notify {Channel} failed; watcher will pick up on the next tick", Channel);
        }
    }
}
