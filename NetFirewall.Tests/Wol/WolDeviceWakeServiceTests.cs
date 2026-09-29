using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models;
using NetFirewall.Models.Wol;
using NetFirewall.Services.Daemon;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Wol;
using NetFirewall.Web.Controllers;

namespace NetFirewall.Tests.Wol;

/// <summary>
/// Waking saved devices from the Web: one, the ticked ones, or all — and what the
/// operator is told when only some of the packets left.
/// </summary>
public class WolDeviceWakeServiceTests
{
    private readonly Mock<IWolDeviceService> _devices = new();
    private readonly Mock<IDaemonClient> _daemon = new();

    private static readonly WolDevice Pc = new() { Id = Guid.NewGuid(), Name = "office-pc", MacAddress = "00:11:32:AB:CD:01", Interface = "ens256" };
    private static readonly WolDevice Nas = new() { Id = Guid.NewGuid(), Name = "nas", MacAddress = "00:11:32:AB:CD:02", Interface = "ens256", Port = 7 };
    private static readonly WolDevice Lab = new() { Id = Guid.NewGuid(), Name = "lab", MacAddress = "00:11:32:AB:CD:03", Interface = "ens256.30" };

    private WolDeviceWakeService Svc(params WolDevice[] saved)
    {
        _devices.Setup(d => d.GetAllAsync(It.IsAny<CancellationToken>())).ReturnsAsync(saved);
        foreach (var d in saved)
            _devices.Setup(s => s.GetByIdAsync(d.Id, It.IsAny<CancellationToken>())).ReturnsAsync(d);
        return new WolDeviceWakeService(_devices.Object, _daemon.Object, NullLogger<WolDeviceWakeService>.Instance);
    }

    private void DaemonSends(params string[] macs)
    {
        _daemon.Setup(c => c.WakeOnLanAsync(It.IsAny<WolWakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync((WolWakeRequest r, CancellationToken _) => macs.Contains(r.Mac)
                ? ServiceResponse<WolWakeResult>.Ok(new WolWakeResult(r.Mac, r.Interface!, "requested", "255.255.255.255", r.Port ?? 9, 3))
                : ServiceResponse<WolWakeResult>.Fail($"{r.Interface} is down (no carrier)."));
    }

    private void VerifyMarked(WolDevice d, Times times) =>
        _devices.Verify(s => s.MarkWokenAsync(d.Id, "marvin", It.IsAny<CancellationToken>()), times);

    // ── one device ─────────────────────────────────────────────────────

    [Fact]
    public async Task Wake_SendsTheSavedInterfaceAndPort_AndStampsIt()
    {
        DaemonSends(Nas.MacAddress);

        var r = await Svc(Nas).WakeAsync(Nas.Id, "marvin");

        Assert.True(r.Success, r.Message);
        Assert.StartsWith("Wake sent to nas on ens256", r.Message);
        _daemon.Verify(c => c.WakeOnLanAsync(new WolWakeRequest(Nas.MacAddress, "ens256", null, 7), It.IsAny<CancellationToken>()));
        VerifyMarked(Nas, Times.Once());
    }

    [Fact]
    public async Task Wake_DaemonRefusal_IsPassedThrough_AndNotStamped()
    {
        DaemonSends();

        var r = await Svc(Pc).WakeAsync(Pc.Id, "marvin");

        Assert.False(r.Success);
        Assert.Contains("no carrier", r.Message);
        VerifyMarked(Pc, Times.Never());
    }

    [Fact]
    public async Task Wake_UnknownDevice()
    {
        var r = await Svc().WakeAsync(Guid.NewGuid(), "marvin");
        Assert.False(r.Success);
        Assert.Equal("Device not found.", r.Message);
    }

    // ── many ───────────────────────────────────────────────────────────

    [Fact]
    public async Task WakeMany_NoSelection_WakesEveryDevice()
    {
        DaemonSends(Pc.MacAddress, Nas.MacAddress, Lab.MacAddress);

        var r = await Svc(Pc, Nas, Lab).WakeManyAsync(null, "marvin");

        Assert.True(r.Success, r.Message);
        Assert.Equal(3, r.Data!.Sent);
        Assert.StartsWith("Wake sent to all 3 devices.", r.Message);
        VerifyMarked(Pc, Times.Once());
        VerifyMarked(Nas, Times.Once());
        VerifyMarked(Lab, Times.Once());
    }

    [Fact]
    public async Task WakeMany_Selection_WakesOnlyThoseAndSkipsUnknownIds()
    {
        DaemonSends(Pc.MacAddress, Nas.MacAddress, Lab.MacAddress);

        var r = await Svc(Pc, Nas, Lab).WakeManyAsync([Nas.Id, Lab.Id, Guid.NewGuid()], "marvin");

        Assert.True(r.Success, r.Message);
        Assert.Equal(["nas", "lab"], r.Data!.Items.Select(i => i.Name));
        Assert.StartsWith("Wake sent to the 2 selected devices.", r.Message);
        VerifyMarked(Pc, Times.Never());
        _daemon.Verify(c => c.WakeOnLanAsync(It.Is<WolWakeRequest>(q => q.Mac == Pc.MacAddress), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task WakeMany_SelectionThatNoLongerExists_IsRefused()
    {
        var r = await Svc(Pc).WakeManyAsync([Guid.NewGuid()], "marvin");

        Assert.False(r.Success);
        Assert.Contains("None of the selected devices", r.Message);
        _daemon.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task WakeMany_NothingSaved()
    {
        var r = await Svc().WakeManyAsync(null, "marvin");
        Assert.False(r.Success);
        Assert.Equal("No saved devices to wake.", r.Message);
    }

    [Fact]
    public async Task WakeMany_Partial_IsAWarningNamingTheFailures_AndStampsOnlyTheSent()
    {
        DaemonSends(Pc.MacAddress, Lab.MacAddress);

        var r = await Svc(Pc, Nas, Lab).WakeManyAsync(null, "marvin");

        Assert.False(r.Success);
        Assert.Equal(2, r.Data!.Sent);
        Assert.StartsWith("Wake sent to 2 of 3 devices. Failed: nas: ens256 is down", r.Message);
        Assert.Equal(["nas"], r.Errors!.Keys);   // Errors present ⇒ the toast renders as a warning
        VerifyMarked(Nas, Times.Never());
        VerifyMarked(Pc, Times.Once());
    }

    [Fact]
    public async Task WakeMany_AllFailForTheSameReason_SaysItOnce()
    {
        _daemon.Setup(c => c.WakeOnLanAsync(It.IsAny<WolWakeRequest>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ServiceResponse<WolWakeResult>.Fail("Daemon unreachable: connection refused"));

        var r = await Svc(Pc, Nas, Lab).WakeManyAsync(null, "marvin");

        Assert.False(r.Success);
        Assert.Equal("No wake was sent: Daemon unreachable: connection refused", r.Message);
        Assert.Null(r.Errors);                   // no per-item Errors ⇒ an error toast, not a warning
    }

    [Fact]
    public async Task WakeMany_StampFailure_StillCountsAsSent()
    {
        DaemonSends(Pc.MacAddress);
        _devices.Setup(s => s.MarkWokenAsync(It.IsAny<Guid>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ThrowsAsync(new InvalidOperationException("db blip"));

        var r = await Svc(Pc).WakeManyAsync(null, "marvin");

        Assert.True(r.Success, r.Message);
        Assert.Equal(1, r.Data!.Sent);
    }

    // ── controller scope guard ─────────────────────────────────────────

    private WakeOnLanController Controller(Mock<IWolDeviceWakeService> waker)
    {
        var c = new WakeOnLanController(_devices.Object, waker.Object, _daemon.Object, new Mock<IFirewallService>().Object);
        c.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
        return c;
    }

    [Theory]
    [InlineData("selected")]   // a selection that never arrived must not become "everything"
    [InlineData(null)]
    [InlineData("everything")]
    public async Task WakeMany_Controller_RefusesSelectedWithoutIdsAndUnknownScopes(string? scope)
    {
        var waker = new Mock<IWolDeviceWakeService>();

        var result = await Controller(waker).WakeMany(scope, [], CancellationToken.None);

        var json = Assert.IsType<JsonResult>(result);
        Assert.False(Assert.IsType<ServiceResponse<WolBatchResult>>(json.Value).Success);
        waker.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task WakeMany_Controller_AllIgnoresIds_SelectedPassesThem()
    {
        var waker = new Mock<IWolDeviceWakeService>();
        waker.Setup(w => w.WakeManyAsync(It.IsAny<IReadOnlyCollection<Guid>?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(ServiceResponse<WolBatchResult>.Ok(new WolBatchResult([]), "ok"));
        var c = Controller(waker);

        await c.WakeMany("all", [Pc.Id], CancellationToken.None);
        await c.WakeMany("selected", [Pc.Id], CancellationToken.None);

        waker.Verify(w => w.WakeManyAsync(null, It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Once);
        waker.Verify(w => w.WakeManyAsync(It.Is<IReadOnlyCollection<Guid>?>(ids => ids != null && ids.Single() == Pc.Id), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Once);
    }
}
