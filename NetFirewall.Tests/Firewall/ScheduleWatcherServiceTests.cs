using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Firewall;

namespace NetFirewall.Tests.Firewall;

public class ScheduleWatcherServiceTests
{
    private static (ScheduleWatcherService watcher, Mock<INftApplyService> nft, Mock<IScheduleService> schedules, Mock<IFirewallService> firewall)
        Build(
            IReadOnlyList<FwSchedule>? schedules = null,
            IReadOnlyList<FwFilterRule>? rules = null)
    {
        var nft = new Mock<INftApplyService>();
        nft.Setup(n => n.ApplyConfigurationAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new NftApplyResult { Success = true });

        var schedSvc = new Mock<IScheduleService>();
        schedSvc.Setup(s => s.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(schedules ?? Array.Empty<FwSchedule>());

        var fw = new Mock<IFirewallService>();
        fw.Setup(f => f.GetFilterRulesAsync(It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(rules ?? Array.Empty<FwFilterRule>());

        var services = new ServiceCollection();
        services.AddSingleton(schedSvc.Object);
        services.AddSingleton(fw.Object);
        services.AddSingleton(nft.Object);
        var sp = services.BuildServiceProvider();

        var watcher = new ScheduleWatcherService(sp, NullLogger<ScheduleWatcherService>.Instance);
        return (watcher, nft, schedSvc, fw);
    }

    [Fact]
    public async Task Tick_ForceApplyOnStart_AlwaysApplies()
    {
        var (watcher, nft, _, _) = Build();
        var applied = await watcher.TickAsync(forceApply: true, CancellationToken.None);
        Assert.True(applied);
        nft.Verify(n => n.ApplyConfigurationAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Tick_UnchangedFingerprint_DoesNotReapply()
    {
        var (watcher, nft, _, _) = Build();
        await watcher.TickAsync(forceApply: true, CancellationToken.None);
        var again = await watcher.TickAsync(forceApply: false, CancellationToken.None);
        Assert.False(again);
        nft.Verify(n => n.ApplyConfigurationAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Tick_NewScheduledRule_Applies()
    {
        var sid = Guid.NewGuid();
        var sched = new FwSchedule
        {
            Id = sid,
            Name = "DIEGO_HOURS",
            DaysOfWeek = new[] { 0, 1, 2, 3, 4, 5, 6 },
            StartTime = new TimeSpan(22, 1, 0),
            EndTime = new TimeSpan(5, 59, 0),
            Timezone = "UTC",
            Enabled = true
        };

        var nft = new Mock<INftApplyService>();
        nft.Setup(n => n.ApplyConfigurationAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new NftApplyResult { Success = true });
        var schedSvc = new Mock<IScheduleService>();
        schedSvc.Setup(s => s.GetAllAsync(It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[] { sched });
        var fw = new Mock<IFirewallService>();
        fw.Setup(f => f.GetFilterRulesAsync(It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(Array.Empty<FwFilterRule>());

        var services = new ServiceCollection();
        services.AddSingleton(schedSvc.Object);
        services.AddSingleton(fw.Object);
        services.AddSingleton(nft.Object);
        var watcher = new ScheduleWatcherService(services.BuildServiceProvider(), NullLogger<ScheduleWatcherService>.Instance);

        await watcher.TickAsync(forceApply: true, CancellationToken.None);

        fw.Setup(f => f.GetFilterRulesAsync(It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(new[]
            {
                new FwFilterRule
                {
                    Id = Guid.NewGuid(),
                    Chain = "forward",
                    Action = "drop",
                    Enabled = true,
                    Priority = 2,
                    ScheduleId = sid,
                    ScheduleInvert = true,
                    SourceAddresses = new[] { "10.0.0.50" }
                }
            });

        var applied = await watcher.TickAsync(forceApply: false, CancellationToken.None);
        Assert.True(applied);
        nft.Verify(n => n.ApplyConfigurationAsync(It.IsAny<CancellationToken>()), Times.Exactly(2));
    }
}
