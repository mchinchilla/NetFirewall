using Microsoft.Extensions.Logging;
using NetFirewall.Models.Firewall;
using Npgsql;

namespace NetFirewall.Services.Firewall;

public sealed class ScheduleService : IScheduleService
{
    private readonly NpgsqlDataSource _ds;
    private readonly ILogger<ScheduleService> _logger;

    public ScheduleService(NpgsqlDataSource ds, ILogger<ScheduleService> logger)
    {
        _ds = ds;
        _logger = logger;
    }

    public async Task<IReadOnlyList<FwSchedule>> GetAllAsync(CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("SELECT * FROM fw_schedules ORDER BY name", conn);
        return await ReadAllAsync(cmd, ct);
    }

    public async Task<FwSchedule?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("SELECT * FROM fw_schedules WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        var rows = await ReadAllAsync(cmd, ct);
        return rows.FirstOrDefault();
    }

    public async Task<FwSchedule> CreateAsync(FwSchedule s, CancellationToken ct = default)
    {
        s.Id = Guid.NewGuid();
        s.CreatedAt = s.UpdatedAt = DateTime.UtcNow;
        Validate(s);

        await using var conn = await _ds.OpenConnectionAsync(ct);
        const string sql = @"
            INSERT INTO fw_schedules (id, name, description, days_of_week, start_time, end_time,
                                      timezone, enabled, created_at, updated_at)
            VALUES (@id, @n, @d, @dow, @start, @end, @tz, @enabled, @ca, @ua)";
        await using var cmd = new NpgsqlCommand(sql, conn);
        Bind(cmd, s);
        await cmd.ExecuteNonQueryAsync(ct);

        _logger.LogInformation("Schedule created: {Name}", s.Name);
        return s;
    }

    public async Task<FwSchedule> UpdateAsync(FwSchedule s, CancellationToken ct = default)
    {
        s.UpdatedAt = DateTime.UtcNow;
        Validate(s);

        await using var conn = await _ds.OpenConnectionAsync(ct);
        const string sql = @"
            UPDATE fw_schedules SET
                name = @n, description = @d, days_of_week = @dow,
                start_time = @start, end_time = @end, timezone = @tz,
                enabled = @enabled, updated_at = @ua
            WHERE id = @id";
        await using var cmd = new NpgsqlCommand(sql, conn);
        Bind(cmd, s);
        await cmd.ExecuteNonQueryAsync(ct);
        return s;
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("DELETE FROM fw_schedules WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        return await cmd.ExecuteNonQueryAsync(ct) > 0;
    }

    private static void Validate(FwSchedule s)
    {
        if (string.IsNullOrWhiteSpace(s.Name))
            throw new ArgumentException("Schedule name is required.");
        if (s.StartTime >= s.EndTime)
            throw new ArgumentException("Start time must be earlier than end time.");
        if (s.DaysOfWeek.Length == 0)
            throw new ArgumentException("Pick at least one day of week.");
        if (s.DaysOfWeek.Any(d => d < 0 || d > 6))
            throw new ArgumentException("Days of week must be 0-6 (Sun-Sat).");
        try { TimeZoneInfo.FindSystemTimeZoneById(s.Timezone); }
        catch { throw new ArgumentException($"Unknown timezone '{s.Timezone}'."); }
    }

    private static void Bind(NpgsqlCommand cmd, FwSchedule s)
    {
        cmd.Parameters.AddWithValue("id", s.Id);
        cmd.Parameters.AddWithValue("n",  s.Name);
        cmd.Parameters.AddWithValue("d",  (object?)s.Description ?? DBNull.Value);
        cmd.Parameters.AddWithValue("dow", s.DaysOfWeek);
        cmd.Parameters.AddWithValue("start", s.StartTime);
        cmd.Parameters.AddWithValue("end",   s.EndTime);
        cmd.Parameters.AddWithValue("tz", s.Timezone);
        cmd.Parameters.AddWithValue("enabled", s.Enabled);
        cmd.Parameters.AddWithValue("ca", s.CreatedAt);
        cmd.Parameters.AddWithValue("ua", s.UpdatedAt);
    }

    private static async Task<List<FwSchedule>> ReadAllAsync(NpgsqlCommand cmd, CancellationToken ct)
    {
        var list = new List<FwSchedule>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            list.Add(new FwSchedule
            {
                Id          = reader.GetGuid(reader.GetOrdinal("id")),
                Name        = reader.GetString(reader.GetOrdinal("name")),
                Description = reader.IsDBNull(reader.GetOrdinal("description")) ? null : reader.GetString(reader.GetOrdinal("description")),
                DaysOfWeek  = (int[])reader["days_of_week"],
                StartTime   = (TimeSpan)reader["start_time"],
                EndTime     = (TimeSpan)reader["end_time"],
                Timezone    = reader.GetString(reader.GetOrdinal("timezone")),
                Enabled     = reader.GetBoolean(reader.GetOrdinal("enabled")),
                CreatedAt   = reader.GetDateTime(reader.GetOrdinal("created_at")),
                UpdatedAt   = reader.GetDateTime(reader.GetOrdinal("updated_at"))
            });
        }
        return list;
    }
}
