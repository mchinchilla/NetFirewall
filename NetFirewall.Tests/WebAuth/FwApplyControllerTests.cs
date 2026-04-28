using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models;
using NetFirewall.Services.Firewall;
using NetFirewall.Web.Controllers;
using NetFirewall.Services.Daemon;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// Coverage for the firewall apply page. Three responsibilities:
///   1. Read-only Preview/QosPreview generate the would-be ruleset locally
///      (no daemon round-trip, no privilege).
///   2. CurrentRuleset reads `nft list ruleset` through the daemon, with a
///      placeholder when the daemon is unreachable.
///   3. Execute / QosExecute hand off to the daemon and emit an HX-Trigger
///      event so the browser refreshes the current-ruleset panel.
/// </summary>
public class FwApplyControllerTests
{
    private readonly Mock<IFirewallService> _firewall = new();
    private readonly Mock<IDaemonClient> _daemon = new();

    private FwApplyController CreateController()
    {
        var c = new FwApplyController(
            _firewall.Object, _daemon.Object, NullLogger<FwApplyController>.Instance);
        c.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
        return c;
    }

    // ── Index ──────────────────────────────────────────────────────────

    [Fact]
    public void Index_ReturnsView()
    {
        Assert.IsType<ViewResult>(CreateController().Index());
    }

    // ── Preview ────────────────────────────────────────────────────────

    [Fact]
    public async Task Preview_ReturnsPartialView_WithGeneratedConfig()
    {
        _firewall.Setup(f => f.GenerateNftablesConfigPreviewAsync(It.IsAny<CancellationToken>()))
                 .ReturnsAsync("flush ruleset\ntable inet filter {}");

        var result = await CreateController().Preview(CancellationToken.None);

        var partial = Assert.IsType<PartialViewResult>(result);
        Assert.Equal("_PreviewBlock", partial.ViewName);
        Assert.Contains("flush ruleset", (string)partial.Model!);
        // No daemon hit — preview is local-only.
        _daemon.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task Preview_GeneratorThrows_ReturnsFailEnvelope_NotCrash()
    {
        _firewall.Setup(f => f.GenerateNftablesConfigPreviewAsync(It.IsAny<CancellationToken>()))
                 .ThrowsAsync(new InvalidOperationException("DB down"));

        var result = await CreateController().Preview(CancellationToken.None);

        // ToHtmxResponse wraps the failure as JSON with status 400.
        var json = Assert.IsType<JsonResult>(result);
        var resp = Assert.IsType<ServiceResponse<string>>(json.Value);
        Assert.False(resp.Success);
        Assert.Contains("DB down", resp.Message);
    }

    // ── CurrentRuleset ─────────────────────────────────────────────────

    [Fact]
    public async Task CurrentRuleset_ReturnsPartialView_WithDaemonOutput()
    {
        _daemon.Setup(d => d.GetCurrentRulesetAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync("table inet filter { chain input { } }");

        var result = await CreateController().CurrentRuleset(CancellationToken.None);

        var partial = Assert.IsType<PartialViewResult>(result);
        Assert.Equal("_CurrentRulesetBlock", partial.ViewName);
        Assert.Contains("table inet filter", (string)partial.Model!);
    }

    [Fact]
    public async Task CurrentRuleset_DaemonReturnsNull_RendersPlaceholderInsteadOfBlankPanel()
    {
        _daemon.Setup(d => d.GetCurrentRulesetAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync((string?)null);

        var result = await CreateController().CurrentRuleset(CancellationToken.None);

        var partial = Assert.IsType<PartialViewResult>(result);
        Assert.Contains("daemon unreachable", (string)partial.Model!);
    }

    // ── Execute ────────────────────────────────────────────────────────

    [Fact]
    public async Task Execute_DelegatesToDaemonApplyFirewall_AndEmitsTriggerEvent()
    {
        var envelope = ServiceResponse<NftApplyResultDto>.Ok(
            new NftApplyResultDto(0, "/var/lib/netfirewall/backups/x.conf", "ok", null), "applied");
        _daemon.Setup(d => d.ApplyFirewallAsync(It.IsAny<CancellationToken>())).ReturnsAsync(envelope);

        var c = CreateController();
        await c.Execute(CancellationToken.None);

        // Both events must be present in HX-Trigger:
        //   - showToast (added by ToHtmxResponse)
        //   - firewallApplied (the panel-refresh trigger this controller adds)
        // Pre-fix the second call clobbered the first; the AttachHxEvent helper
        // now merges JSON so both fire on the browser.
        var hx = c.Response.Headers["HX-Trigger"].ToString();
        Assert.Contains("firewallApplied", hx);
        Assert.Contains("showToast", hx);
    }

    [Fact]
    public async Task Execute_DaemonFailureEnvelope_StillEmitsTriggerEvent()
    {
        // The trigger fires either way — the browser refresh shows whatever
        // the daemon left in nft (a successful rollback or a half-applied state).
        _daemon.Setup(d => d.ApplyFirewallAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync(ServiceResponse<NftApplyResultDto>.Fail("nft syntax error"));

        var c = CreateController();
        await c.Execute(CancellationToken.None);

        var hx = c.Response.Headers["HX-Trigger"].ToString();
        Assert.Contains("firewallApplied", hx);
    }

    // ── QosPreview ─────────────────────────────────────────────────────

    [Fact]
    public async Task QosPreview_ReturnsTcScript_Local()
    {
        _firewall.Setup(f => f.GenerateTcScriptAsync(It.IsAny<CancellationToken>()))
                 .ReturnsAsync("#!/bin/bash\ntc qdisc replace ...");

        var result = await CreateController().QosPreview(CancellationToken.None);

        var partial = Assert.IsType<PartialViewResult>(result);
        Assert.Equal("_PreviewBlock", partial.ViewName);
        Assert.Contains("tc qdisc replace", (string)partial.Model!);
        _daemon.VerifyNoOtherCalls();
    }

    [Fact]
    public async Task QosPreview_GeneratorThrows_ReturnsFailEnvelope()
    {
        _firewall.Setup(f => f.GenerateTcScriptAsync(It.IsAny<CancellationToken>()))
                 .ThrowsAsync(new InvalidOperationException("no qos config"));

        var result = await CreateController().QosPreview(CancellationToken.None);

        var json = Assert.IsType<JsonResult>(result);
        var resp = Assert.IsType<ServiceResponse<string>>(json.Value);
        Assert.False(resp.Success);
        Assert.Contains("no qos config", resp.Message);
    }

    // ── QosExecute ─────────────────────────────────────────────────────

    [Fact]
    public async Task QosExecute_DelegatesToDaemonApplyQos_AndEmitsTriggerEvent()
    {
        var envelope = ServiceResponse<NftApplyResultDto>.Ok(
            new NftApplyResultDto(0, null, "tc applied", null), "qos applied");
        _daemon.Setup(d => d.ApplyQosAsync(It.IsAny<CancellationToken>())).ReturnsAsync(envelope);

        var c = CreateController();
        await c.QosExecute(CancellationToken.None);

        var hx = c.Response.Headers["HX-Trigger"].ToString();
        Assert.Contains("qosApplied", hx);
        Assert.Contains("showToast", hx);
    }
}
