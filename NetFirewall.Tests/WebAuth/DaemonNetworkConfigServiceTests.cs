using Moq;
using NetFirewall.Models;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.System;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Web.Daemon;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// Decorator that splits read-only operations (delegated to the in-process
/// writer) from mutations (proxied to the daemon). The split exists because
/// generating a config doesn't need root and round-tripping it through a UDS
/// is wasted latency — but applying it does.
///
/// Pin both halves so a future refactor can't accidentally route a read
/// through the daemon (latency tax) or send an apply through the local
/// writer (security regression: Web shouldn't have CAP_NET_ADMIN).
/// </summary>
public class DaemonNetworkConfigServiceTests
{
    private readonly Mock<IDaemonClient> _daemon = new();
    private readonly Mock<INetworkConfigService> _localWriter = new();
    private readonly Mock<IFirewallService> _firewall = new();

    private DaemonNetworkConfigService Create() =>
        new(_daemon.Object, _localWriter.Object, _firewall.Object);

    private static FwInterface Iface(Guid? id = null) => new()
    {
        Id = id ?? Guid.NewGuid(), Name = "eth0", AddressingMode = "static"
    };

    // ── Read-only ops: hit the local writer, never the daemon ──────────

    [Fact]
    public void ConfigMethod_ReadsFromLocalWriter()
    {
        _localWriter.SetupGet(w => w.ConfigMethod).Returns(NetworkConfigMethod.Netplan);

        var method = Create().ConfigMethod;

        Assert.Equal(NetworkConfigMethod.Netplan, method);
        _daemon.VerifyNoOtherCalls();
    }

    [Fact]
    public void GetConfigFilePath_DelegatesToLocalWriter()
    {
        var iface = Iface();
        _localWriter.Setup(w => w.GetConfigFilePath(iface)).Returns("/etc/netplan/x.yaml");

        var path = Create().GetConfigFilePath(iface);

        Assert.Equal("/etc/netplan/x.yaml", path);
        _daemon.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task GenerateConfigAsync_DelegatesToLocalWriter_NeverHitsDaemon()
    {
        var iface = Iface();
        _localWriter.Setup(w => w.GenerateConfigAsync(iface, It.IsAny<IEnumerable<FwStaticRoute>?>()))
                    .ReturnsAsync("# generated config");

        var cfg = await Create().GenerateConfigAsync(iface);

        Assert.Equal("# generated config", cfg);
        _daemon.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task ValidateConfigAsync_DelegatesToLocalWriter()
    {
        _localWriter.Setup(w => w.ValidateConfigAsync("the-cfg")).ReturnsAsync(true);

        var ok = await Create().ValidateConfigAsync("the-cfg");

        Assert.True(ok);
        _daemon.VerifyNoOtherCalls();
    }

    // ── Apply ops: hit the daemon, never the local writer's apply ──────

    [Fact]
    public async Task ApplyConfigAsync_HitsDaemonApplyInterface_NotLocalApply()
    {
        var iface = Iface();
        _daemon.Setup(d => d.ApplyInterfaceAsync(iface.Id, It.IsAny<CancellationToken>()))
               .ReturnsAsync(ServiceResponse<NetworkApplyResult>.Ok(
                   new NetworkApplyResult { Success = true, Message = "applied" }));

        var result = await Create().ApplyConfigAsync(iface);

        Assert.True(result.Success);
        Assert.Equal("applied", result.Message);
        _daemon.Verify(d => d.ApplyInterfaceAsync(iface.Id, It.IsAny<CancellationToken>()), Times.Once);
        // Local apply must NOT have been called — that path runs as the Web user
        // (zero capabilities) and would silently fail.
        _localWriter.Verify(w => w.ApplyConfigAsync(It.IsAny<FwInterface>(), It.IsAny<IEnumerable<FwStaticRoute>?>()),
            Times.Never);
    }

    [Fact]
    public async Task ApplyConfigAsync_DaemonEnvelopeWithoutData_StillReturnsResult_NotNull()
    {
        // Defensive: if the daemon returns Success=true but an empty Data payload
        // (older daemon, schema drift), the decorator must synthesize a sane
        // NetworkApplyResult instead of NRE.
        var iface = Iface();
        _daemon.Setup(d => d.ApplyInterfaceAsync(iface.Id, It.IsAny<CancellationToken>()))
               .ReturnsAsync(new ServiceResponse<NetworkApplyResult>
               {
                   Success = true, Message = "ok"
               });

        var result = await Create().ApplyConfigAsync(iface);

        Assert.True(result.Success);
        Assert.Equal("ok", result.Message);
        Assert.Equal(0, result.ExitCode);
    }

    [Fact]
    public async Task ApplyConfigAsync_DaemonFailureEnvelopeWithoutData_SynthesizesFailureResult()
    {
        var iface = Iface();
        _daemon.Setup(d => d.ApplyInterfaceAsync(iface.Id, It.IsAny<CancellationToken>()))
               .ReturnsAsync(ServiceResponse<NetworkApplyResult>.Fail("daemon refused"));

        var result = await Create().ApplyConfigAsync(iface);

        Assert.False(result.Success);
        Assert.Contains("daemon refused", result.Message);
        Assert.Equal(-1, result.ExitCode);
    }

    [Fact]
    public async Task RestartNetworkingAsync_HitsDaemon_NotLocalWriter()
    {
        _daemon.Setup(d => d.RestartNetworkingAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync(ServiceResponse<NetworkApplyResult>.Ok(
                   new NetworkApplyResult { Success = true, Message = "restarted" }));

        var result = await Create().RestartNetworkingAsync();

        Assert.True(result.Success);
        Assert.Equal("restarted", result.Message);
        _localWriter.Verify(w => w.RestartNetworkingAsync(), Times.Never);
    }
}
