using System.Net;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.System;
using NetFirewall.Services.Network;
using Xunit;

namespace NetFirewall.Tests.Network;

/// <summary>
/// Stand-in writer for non-Linux dev hosts: generation works (so the UI can
/// preview) but apply/restart deliberately fail with explanatory messages
/// instead of mutating the host filesystem.
/// </summary>
public class NoOpNetworkConfigServiceTests
{
    private readonly NoOpNetworkConfigService _svc = new();

    [Fact]
    public void ConfigMethod_ReportsUnknown()
    {
        Assert.Equal(NetworkConfigMethod.Unknown, _svc.ConfigMethod);
    }

    [Fact]
    public void GetConfigFilePath_ReturnsPlaceholderInsteadOfRealPath()
    {
        // Defensive: we never want callers to actually write to a real path on the host,
        // so the placeholder must NOT look like a writable location.
        var path = _svc.GetConfigFilePath(new FwInterface { Name = "eth0" });
        Assert.Contains("<no writer for this platform>", path);
        Assert.EndsWith("eth0", path);
    }

    [Fact]
    public async Task GenerateConfigAsync_ProducesPreviewWithKeyFields()
    {
        var iface = new FwInterface
        {
            Name = "eth0",
            Type = "WAN",
            Role = "primary_wan",
            AddressingMode = "static",
            IpAddress = IPAddress.Parse("192.168.1.10"),
            SubnetMask = IPAddress.Parse("255.255.255.0"),
            Gateway = IPAddress.Parse("192.168.1.1"),
            DnsServers = new[] { IPAddress.Parse("8.8.8.8") },
            Mtu = 1500,
            VlanId = 100,
            VlanParent = "eth0",
            AutoStart = true
        };

        var preview = await _svc.GenerateConfigAsync(iface);

        Assert.Contains("preview only", preview);
        Assert.Contains("Interface : eth0", preview);
        Assert.Contains("Type      : WAN / primary_wan", preview);
        Assert.Contains("Static 192.168.1.10/255.255.255.0 via 192.168.1.1", preview);
        Assert.Contains("DNS       : 8.8.8.8", preview);
        Assert.Contains("MTU       : 1500", preview);
        Assert.Contains("VLAN      : 100 on eth0", preview);
        Assert.Contains("Apply will fail on this platform", preview);
    }

    [Fact]
    public async Task GenerateConfigAsync_DhcpModeReportsDhcp()
    {
        var iface = new FwInterface { Name = "eth0", Type = "WAN", AddressingMode = "dhcp" };
        var preview = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("Addressing: DHCP", preview);
    }

    [Fact]
    public async Task GenerateConfigAsync_DisabledModeReportsDisabled()
    {
        var iface = new FwInterface { Name = "eth0", Type = "WAN", AddressingMode = "disabled" };
        var preview = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("Addressing: Disabled", preview);
    }

    [Fact]
    public async Task GenerateConfigAsync_NoDnsRendersNone()
    {
        var iface = new FwInterface { Name = "eth0", Type = "LAN", DnsServers = null };
        var preview = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("DNS       : (none)", preview);
    }

    [Fact]
    public async Task GenerateConfigAsync_NoMtuRendersDefault()
    {
        var iface = new FwInterface { Name = "eth0", Type = "LAN", Mtu = null };
        var preview = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("MTU       : default", preview);
    }

    [Fact]
    public async Task GenerateConfigAsync_NoVlanRendersNone()
    {
        var iface = new FwInterface { Name = "eth0", Type = "LAN", VlanId = null };
        var preview = await _svc.GenerateConfigAsync(iface);
        Assert.Contains("VLAN      : none", preview);
    }

    // ── apply / restart deliberate failures ────────────────────────────

    [Fact]
    public async Task ApplyConfigAsync_AlwaysFailsWithExplanatoryMessage()
    {
        var iface = new FwInterface { Name = "eth0" };
        var result = await _svc.ApplyConfigAsync(iface);

        Assert.False(result.Success);
        Assert.Equal(-1, result.ExitCode);
        Assert.Contains("not supported on this platform", result.Message);
        // Path is still surfaced so the UI can show what would have been written.
        Assert.Contains("eth0", result.ConfigFilePath);
    }

    [Fact]
    public async Task RestartNetworkingAsync_AlwaysFails()
    {
        var result = await _svc.RestartNetworkingAsync();

        Assert.False(result.Success);
        Assert.Equal(-1, result.ExitCode);
        Assert.Contains("not supported", result.Message);
    }

    [Fact]
    public async Task ValidateConfigAsync_AcceptsAnyNonEmptyText()
    {
        Assert.True(await _svc.ValidateConfigAsync("anything goes"));
        Assert.True(await _svc.ValidateConfigAsync("# preview"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("\n\t  \r\n")]
    public async Task ValidateConfigAsync_RejectsEmptyOrWhitespace(string config)
    {
        Assert.False(await _svc.ValidateConfigAsync(config));
    }
}
