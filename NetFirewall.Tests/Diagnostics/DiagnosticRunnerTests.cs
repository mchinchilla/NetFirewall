using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Diagnostics;

namespace NetFirewall.Tests.Diagnostics;

public class DiagnosticRunnerTests
{
    private static readonly Guid RunId = Guid.NewGuid();

    private static (DiagnosticRunner runner, Mock<IDiagnosticRunStore> store, DiagnosticGate gate) Make()
    {
        var store = new Mock<IDiagnosticRunStore>();
        store.Setup(s => s.StartAsync(It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<object?>(), It.IsAny<CancellationToken>()))
             .ReturnsAsync(RunId);
        var gate = new DiagnosticGate();
        var runner = new DiagnosticRunner(store.Object, gate, NullLogger<DiagnosticRunner>.Instance);
        return (runner, store, gate);
    }

    [Fact]
    public async Task Verdict_IsSuccess_AndRowIsOpenedThenClosed()
    {
        var (runner, store, _) = Make();

        var env = await runner.RunAsync(DiagTools.Ping, DiagFamilies.Ping, "1.1.1.1", "marvin", new { target = "1.1.1.1" },
            TimeSpan.FromSeconds(5), _ => Task.FromResult(new DiagOutcome<string>("pong", DiagRunStatus.Ok, "3/3 replies")));

        Assert.True(env.Success);
        Assert.Equal("3/3 replies", env.Message);
        Assert.Equal(RunId, env.Data!.RunId);
        Assert.Equal(DiagRunStatus.Ok, env.Data.Status);
        Assert.Equal("pong", env.Data.Result);
        store.Verify(s => s.StartAsync(DiagTools.Ping, "1.1.1.1", "marvin", It.IsAny<object?>(), It.IsAny<CancellationToken>()), Times.Once);
        store.Verify(s => s.FinishAsync(RunId, DiagRunStatus.Ok, "pong", "3/3 replies", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task FailVerdict_IsStillASuccessfulRun()
    {
        // 100 % packet loss is a finding, not a broken tool.
        var (runner, _, _) = Make();

        var env = await runner.RunAsync(DiagTools.Ping, DiagFamilies.Ping, null, null, null,
            TimeSpan.FromSeconds(5), _ => Task.FromResult(new DiagOutcome<string>("lost", DiagRunStatus.Fail, "0/3 replies")));

        Assert.True(env.Success);
        Assert.Equal(DiagRunStatus.Fail, env.Data!.Status);
    }

    [Fact]
    public async Task BodyPastBudget_IsTimeout_NotError()
    {
        var (runner, store, _) = Make();

        var env = await runner.RunAsync<string>(DiagTools.RouteGet, DiagFamilies.Route, null, null, null,
            TimeSpan.FromMilliseconds(50), async token =>
            {
                await Task.Delay(TimeSpan.FromSeconds(5), token);
                return new DiagOutcome<string>("never", DiagRunStatus.Ok, "never");
            });

        Assert.False(env.Success);
        Assert.Equal(DiagRunStatus.Timeout, env.Data!.Status);
        Assert.Contains("Timed out", env.Message);
        store.Verify(s => s.FinishAsync(RunId, DiagRunStatus.Timeout, null, It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task BodyThrows_IsError_WithTheMessage()
    {
        var (runner, store, _) = Make();

        var env = await runner.RunAsync<string>(DiagTools.Conntrack, DiagFamilies.Conntrack, null, null, null,
            TimeSpan.FromSeconds(5), _ => throw new InvalidOperationException("conntrack: command not found"));

        Assert.False(env.Success);
        Assert.Equal(DiagRunStatus.Error, env.Data!.Status);
        Assert.Equal("conntrack: command not found", env.Message);
        store.Verify(s => s.FinishAsync(RunId, DiagRunStatus.Error, null, "conntrack: command not found", It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task GateBusy_IsRefused_NotPersisted_AndSlotIsReleasedAfterwards()
    {
        var (runner, store, gate) = Make();
        var held = gate.TryEnter(DiagFamilies.Doctor)!;

        var env = await runner.RunAsync(DiagTools.VpnDoctor, DiagFamilies.Doctor, null, null, null,
            TimeSpan.FromSeconds(5), _ => Task.FromResult(new DiagOutcome<string>("x", DiagRunStatus.Ok, "x")));

        Assert.False(env.Success);
        Assert.Equal(DiagRunStatus.Busy, env.Data!.Status);
        Assert.Contains("already in progress", env.Message);
        store.Verify(s => s.StartAsync(It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<object?>(), It.IsAny<CancellationToken>()), Times.Never);

        held.Dispose();
        var again = await runner.RunAsync(DiagTools.VpnDoctor, DiagFamilies.Doctor, null, null, null,
            TimeSpan.FromSeconds(5), _ => Task.FromResult(new DiagOutcome<string>("x", DiagRunStatus.Ok, "x")));
        Assert.True(again.Success);
    }

    [Fact]
    public async Task StoreDown_ToolStillRuns()
    {
        var (runner, store, _) = Make();
        store.Setup(s => s.StartAsync(It.IsAny<string>(), It.IsAny<string?>(), It.IsAny<string?>(), It.IsAny<object?>(), It.IsAny<CancellationToken>()))
             .ThrowsAsync(new Npgsql.NpgsqlException("connection refused"));

        var env = await runner.RunAsync(DiagTools.Ping, DiagFamilies.Ping, null, null, null,
            TimeSpan.FromSeconds(5), _ => Task.FromResult(new DiagOutcome<string>("pong", DiagRunStatus.Ok, "ok")));

        Assert.True(env.Success);
        Assert.NotEqual(Guid.Empty, env.Data!.RunId);
        store.Verify(s => s.FinishAsync(It.IsAny<Guid>(), It.IsAny<string>(), It.IsAny<object?>(), It.IsAny<string?>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}
