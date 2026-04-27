using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Firewall;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Firewall;

/// <summary>
/// Real-Postgres CRUD coverage for <see cref="ScheduleService"/>. Exercises the
/// non-trivial Npgsql mappings — <c>int[]</c> for days_of_week and <c>TimeSpan</c>
/// for time-of-day — that aren't testable in-memory.
/// </summary>
[Collection("Postgres")]
public sealed class ScheduleServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private ScheduleService _svc = null!;

    public ScheduleServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _svc = new ScheduleService(_pg.DataSource, NullLogger<ScheduleService>.Instance);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private static FwSchedule MakeBusinessHours(string name = "business")
        => new()
        {
            Name = name,
            Description = "Mon-Fri 9-17",
            DaysOfWeek = new[] { 1, 2, 3, 4, 5 },
            StartTime = new TimeSpan(9, 0, 0),
            EndTime = new TimeSpan(17, 0, 0),
            Timezone = "America/New_York",
            Enabled = true
        };

    // ── Create + round-trip ────────────────────────────────────────────

    [Fact]
    public async Task CreateAsync_PersistsAllFields_AndRoundTripsCorrectly()
    {
        var src = MakeBusinessHours();
        var created = await _svc.CreateAsync(src);

        Assert.NotEqual(Guid.Empty, created.Id);

        var fetched = await _svc.GetByIdAsync(created.Id);
        Assert.NotNull(fetched);
        Assert.Equal("business", fetched!.Name);
        Assert.Equal("Mon-Fri 9-17", fetched.Description);
        Assert.Equal(new[] { 1, 2, 3, 4, 5 }, fetched.DaysOfWeek); // int[] round-trip
        Assert.Equal(new TimeSpan(9, 0, 0), fetched.StartTime);    // TimeSpan/time round-trip
        Assert.Equal(new TimeSpan(17, 0, 0), fetched.EndTime);
        Assert.Equal("America/New_York", fetched.Timezone);
        Assert.True(fetched.Enabled);
    }

    [Fact]
    public async Task CreateAsync_NullDescription_RoundTripsAsNull()
    {
        var s = MakeBusinessHours();
        s.Description = null;
        var created = await _svc.CreateAsync(s);

        var fetched = await _svc.GetByIdAsync(created.Id);
        Assert.Null(fetched!.Description);
    }

    [Fact]
    public async Task CreateAsync_AllSevenDays_RoundTrip()
    {
        var s = MakeBusinessHours("always");
        s.DaysOfWeek = new[] { 0, 1, 2, 3, 4, 5, 6 };
        var created = await _svc.CreateAsync(s);

        var fetched = await _svc.GetByIdAsync(created.Id);
        Assert.Equal(new[] { 0, 1, 2, 3, 4, 5, 6 }, fetched!.DaysOfWeek);
    }

    [Fact]
    public async Task CreateAsync_GeneratesNewIdEvenIfCallerProvidesOne()
    {
        // Service contract: assigns its own Guid.NewGuid() in CreateAsync.
        var s = MakeBusinessHours();
        s.Id = Guid.NewGuid();
        var supplied = s.Id;

        var created = await _svc.CreateAsync(s);

        Assert.NotEqual(supplied, created.Id);
    }

    // ── Validation errors ──────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public async Task CreateAsync_EmptyName_Throws(string? name)
    {
        var s = MakeBusinessHours();
        s.Name = name!;
        await Assert.ThrowsAsync<ArgumentException>(() => _svc.CreateAsync(s));
    }

    [Fact]
    public async Task CreateAsync_StartTimeNotBeforeEnd_Throws()
    {
        var s = MakeBusinessHours();
        s.StartTime = new TimeSpan(17, 0, 0);
        s.EndTime = new TimeSpan(9, 0, 0);
        await Assert.ThrowsAsync<ArgumentException>(() => _svc.CreateAsync(s));
    }

    [Fact]
    public async Task CreateAsync_EmptyDaysOfWeek_Throws()
    {
        var s = MakeBusinessHours();
        s.DaysOfWeek = Array.Empty<int>();
        await Assert.ThrowsAsync<ArgumentException>(() => _svc.CreateAsync(s));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(7)]
    [InlineData(99)]
    public async Task CreateAsync_DayOfWeekOutOfRange_Throws(int badDay)
    {
        var s = MakeBusinessHours();
        s.DaysOfWeek = new[] { 1, badDay, 3 };
        await Assert.ThrowsAsync<ArgumentException>(() => _svc.CreateAsync(s));
    }

    [Fact]
    public async Task CreateAsync_UnknownTimezone_Throws()
    {
        var s = MakeBusinessHours();
        s.Timezone = "Mars/Olympus_Mons";
        await Assert.ThrowsAsync<ArgumentException>(() => _svc.CreateAsync(s));
    }

    // ── DB-level constraints ───────────────────────────────────────────

    [Fact]
    public async Task CreateAsync_DuplicateName_FailsAtDatabase()
    {
        await _svc.CreateAsync(MakeBusinessHours("dupes"));
        // The UNIQUE(name) constraint on fw_schedules should reject the second insert.
        await Assert.ThrowsAsync<PostgresException>(() => _svc.CreateAsync(MakeBusinessHours("dupes")));
    }

    // ── Get ─────────────────────────────────────────────────────────────

    [Fact]
    public async Task GetByIdAsync_UnknownId_ReturnsNull()
    {
        Assert.Null(await _svc.GetByIdAsync(Guid.NewGuid()));
    }

    [Fact]
    public async Task GetAllAsync_OrdersByName()
    {
        await _svc.CreateAsync(MakeBusinessHours("zulu"));
        await _svc.CreateAsync(MakeBusinessHours("alpha"));
        await _svc.CreateAsync(MakeBusinessHours("mike"));

        var all = await _svc.GetAllAsync();

        Assert.Equal(new[] { "alpha", "mike", "zulu" }, all.Select(s => s.Name));
    }

    // ── Update ─────────────────────────────────────────────────────────

    [Fact]
    public async Task UpdateAsync_ModifiesFields_AndPersists()
    {
        var s = await _svc.CreateAsync(MakeBusinessHours());

        s.Name = "extended";
        s.EndTime = new TimeSpan(20, 0, 0);
        s.Enabled = false;
        s.DaysOfWeek = new[] { 0, 6 };

        await _svc.UpdateAsync(s);

        var fetched = await _svc.GetByIdAsync(s.Id);
        Assert.Equal("extended", fetched!.Name);
        Assert.Equal(new TimeSpan(20, 0, 0), fetched.EndTime);
        Assert.False(fetched.Enabled);
        Assert.Equal(new[] { 0, 6 }, fetched.DaysOfWeek);
    }

    [Fact]
    public async Task UpdateAsync_AlsoValidates_RejectsBadInput()
    {
        var s = await _svc.CreateAsync(MakeBusinessHours());
        s.Name = ""; // invalid

        await Assert.ThrowsAsync<ArgumentException>(() => _svc.UpdateAsync(s));

        // Original row unchanged.
        var fetched = await _svc.GetByIdAsync(s.Id);
        Assert.Equal("business", fetched!.Name);
    }

    // ── Delete ─────────────────────────────────────────────────────────

    [Fact]
    public async Task DeleteAsync_ExistingRow_ReturnsTrue_AndRowGone()
    {
        var s = await _svc.CreateAsync(MakeBusinessHours());

        var ok = await _svc.DeleteAsync(s.Id);

        Assert.True(ok);
        Assert.Null(await _svc.GetByIdAsync(s.Id));
    }

    [Fact]
    public async Task DeleteAsync_UnknownId_ReturnsFalse()
    {
        Assert.False(await _svc.DeleteAsync(Guid.NewGuid()));
    }
}
