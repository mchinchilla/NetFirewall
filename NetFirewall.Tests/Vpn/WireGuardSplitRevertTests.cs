using System.Text.Json;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Vpn;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Vpn;

/// <summary>
/// Revert of a WireGuard split, against the real <c>vpn_split_journal</c>. The catalog services
/// and the kernel are mocked: what is under test is the journal state machine and the order of
/// the kernel steps — including that the revert holds the journal row, so an operator confirming
/// in the Web while the daemon's watchdog reverts can't both succeed.
/// </summary>
[Collection("Postgres")]
public sealed class WireGuardSplitRevertTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private readonly Guid _sourceId = Guid.NewGuid();
    private readonly Guid _serverId = Guid.NewGuid();
    private readonly Mock<IWireGuardService> _wg = new();
    private readonly Mock<IWireGuardSplitKernel> _kernel = new();

    public WireGuardSplitRevertTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();

        _wg.Setup(w => w.GetServerByIdAsync(_sourceId, It.IsAny<CancellationToken>()))
           .ReturnsAsync(new WgServer { Id = _sourceId, Name = "wg0" });
        _wg.Setup(w => w.GetServerByIdAsync(_serverId, It.IsAny<CancellationToken>()))
           .ReturnsAsync((WgServer?)null);   // the new server row is already gone: keep the test on the journal
        _wg.Setup(w => w.SaveServerAsync(It.IsAny<WgServer>(), It.IsAny<CancellationToken>()))
           .ReturnsAsync((WgServer s, CancellationToken _) => s);
        _wg.Setup(w => w.GetPeersAsync(It.IsAny<Guid>(), It.IsAny<CancellationToken>()))
           .ReturnsAsync(Array.Empty<WgPeer>());

        _kernel.Setup(k => k.ApplyInterfaceAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()))
               .ReturnsAsync(ServiceResponse<object>.Ok(new { }, "ok"));
        _kernel.Setup(k => k.ApplyFirewallAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync(ServiceResponse<object>.Ok(new { }, "ok"));
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private WireGuardSplitService Service() => new(
        _wg.Object, Mock.Of<IVpnRoutingService>(), Mock.Of<IFirewallService>(), _kernel.Object,
        _pg.DataSource, NullLogger<WireGuardSplitService>.Instance);

    private async Task<Guid> InsertPendingAsync()
    {
        var snapshot = JsonSerializer.Serialize(new
        {
            SourceId = _sourceId, AddressCidr = "10.8.0.1/24, 10.200.0.2/32", ListenPort = 51820,
            Mode = "server", TableOff = false, ServerId = _serverId, MovedPeerIds = Array.Empty<Guid>(),
        });
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand("""
            INSERT INTO vpn_split_journal (source_name, server_name, snapshot, state, deadline)
            VALUES ('wg0', 'wg1', @snap::jsonb, 'pending', now() - interval '1 minute') RETURNING id
            """, conn);
        cmd.Parameters.AddWithValue("snap", snapshot);
        return (Guid)(await cmd.ExecuteScalarAsync())!;
    }

    private async Task<string> StateAsync(Guid id)
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand("SELECT state FROM vpn_split_journal WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        return (string)(await cmd.ExecuteScalarAsync())!;
    }

    [Fact]
    public async Task Revert_RestoresTheSource_ThroughTheKernel_AndMarksReverted()
    {
        var id = await InsertPendingAsync();

        var r = await Service().RevertAsync(id, "not confirmed in time");

        Assert.True(r.Success, r.Message);
        Assert.Equal("reverted", await StateAsync(id));
        _wg.Verify(w => w.SaveServerAsync(It.Is<WgServer>(s => s.Id == _sourceId && s.ListenPort == 51820 && s.Mode == "server"),
            It.IsAny<CancellationToken>()), Times.Once);
        _kernel.Verify(k => k.ApplyInterfaceAsync("wg0", It.IsAny<CancellationToken>()), Times.Once);
        _kernel.Verify(k => k.ApplyFirewallAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Revert_KernelRefuses_IsRecordedAsRevertFailed_NotSilentlyReverted()
    {
        // What the Web-hosted watchdog used to hit on every run: the daemon answered 401.
        _kernel.Setup(k => k.ApplyInterfaceAsync("wg0", It.IsAny<CancellationToken>()))
               .ReturnsAsync(ServiceResponse<object>.Fail("401 Unauthorized"));
        var id = await InsertPendingAsync();

        var r = await Service().RevertAsync(id, "not confirmed in time");

        Assert.False(r.Success);
        Assert.Equal("revert_failed", await StateAsync(id));
    }

    [Fact]
    public async Task Revert_NoPendingSplit_IsRefused()
    {
        var r = await Service().RevertAsync(Guid.NewGuid(), "x");
        Assert.False(r.Success);
    }

    [Fact]
    public async Task Confirm_WhileARevertIsInFlight_WaitsForIt_AndFindsNothingToConfirm()
    {
        var firewallReached = new TaskCompletionSource();
        var release = new TaskCompletionSource<ServiceResponse<object>>();
        _kernel.Setup(k => k.ApplyFirewallAsync(It.IsAny<CancellationToken>()))
               .Returns(() => { firewallReached.TrySetResult(); return release.Task; });
        var id = await InsertPendingAsync();

        var revert = Service().RevertAsync(id, "not confirmed in time");
        await firewallReached.Task.WaitAsync(TimeSpan.FromSeconds(10));

        var confirm = Service().ConfirmAsync(id);
        // The revert holds the row: the confirm must not get through while it runs.
        Assert.NotSame(confirm, await Task.WhenAny(confirm, Task.Delay(500)));

        release.SetResult(ServiceResponse<object>.Ok(new { }, "ok"));
        var reverted = await revert;
        var confirmed = await confirm.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.True(reverted.Success, reverted.Message);
        Assert.False(confirmed.Success);
        Assert.Equal("reverted", await StateAsync(id));
    }
}

/// <summary>
/// The watchdog must run where the revert can reach the kernel without an operator session —
/// the daemon. In the Web its daemon calls carried no session and were refused with 401, so an
/// unconfirmed split was never reverted.
/// </summary>
public class WireGuardSplitWatchdogPlacementTests
{
    private static string Read(string relative)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "NetFirewall.Web"))) dir = dir.Parent;
        return File.ReadAllText(Path.Combine(dir!.FullName, relative));
    }

    [Fact]
    public void Daemon_HostsTheWatchdog_WithTheInProcessKernel()
    {
        var daemon = Read("NetFirewall.Daemon/Program.cs");
        Assert.Contains("AddHostedService<NetFirewall.Services.Vpn.WireGuardSplitWatchdog>", daemon);
        Assert.Contains("NetFirewall.Services.Vpn.InProcessWireGuardSplitKernel", daemon);
    }

    [Fact]
    public void Web_DoesNotHostTheWatchdog_AndUsesTheDaemonKernel()
    {
        var web = Read("NetFirewall.Web/Program.cs");
        Assert.DoesNotContain("WireGuardSplitWatchdog", web);
        Assert.Contains("NetFirewall.Services.Vpn.DaemonWireGuardSplitKernel", web);
    }

    [Fact]
    public void InProcessKernel_NeverGoesThroughTheDaemonClient()
    {
        var ctorParams = typeof(InProcessWireGuardSplitKernel).GetConstructors().Single().GetParameters();
        Assert.DoesNotContain(ctorParams, p => p.ParameterType == typeof(NetFirewall.Services.Daemon.IDaemonClient));
    }
}
