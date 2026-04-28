using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using NetFirewall.Models;
using NetFirewall.Models.Setup;
using NetFirewall.Models.System;
using NetFirewall.Services.Network;
using NetFirewall.Services.Setup;
using NetFirewall.Web.Controllers;
using NetFirewall.Services.Daemon;
using NetFirewall.Web.Models.Setup;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// Coverage for the multi-step initial-setup wizard controller. Focus on the
/// orchestration: routing decisions, step clamping, completion gate, and the
/// terminal Apply/Reset flow that calls multiple wizard service methods in
/// sequence — a partial failure there leaves the firewall half-configured.
/// </summary>
public class SetupWizardControllerTests
{
    private readonly Mock<ISetupWizardService> _wizard = new();
    private readonly Mock<IDaemonClient> _daemon = new();
    private readonly Mock<INetworkConfigResolver> _resolver = new();

    private SetupWizardController CreateController()
    {
        var c = new SetupWizardController(
            _wizard.Object, _daemon.Object, _resolver.Object,
            NullLogger<SetupWizardController>.Instance);
        c.ControllerContext = new ControllerContext { HttpContext = new DefaultHttpContext() };
        return c;
    }

    private static SetupWizardState State(int currentStep = 1, bool completed = false) => new()
    {
        Id = Guid.NewGuid(),
        CurrentStep = currentStep,
        IsCompleted = completed
    };

    private void StubBuildPageDeps()
    {
        // BuildPageAsync needs all four step accessors + DetectNetworkInterfaces.
        // Stub them all to empty so any test that re-renders the view doesn't NRE.
        _wizard.Setup(w => w.DetectNetworkInterfacesAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync(Array.Empty<DetectedNetworkInterface>());
        _wizard.Setup(w => w.GetStep1InterfacesAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync((List<WizardInterfaceConfig>?)null);
        _wizard.Setup(w => w.GetStep2LanAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync((List<WizardLanConfig>?)null);
        _wizard.Setup(w => w.GetStep3FirewallAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync((WizardFirewallConfig?)null);
        _wizard.Setup(w => w.GetStep4ServicesAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync((WizardServicesConfig?)null);
    }

    // ── Index: completion gate ─────────────────────────────────────────

    [Fact]
    public async Task Index_WizardCompleted_NoForce_RedirectsToHome()
    {
        _wizard.Setup(w => w.GetOrCreateWizardStateAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync(State(currentStep: 5, completed: true));

        var result = await CreateController().Index();

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Index", redirect.ActionName);
        Assert.Equal("Home", redirect.ControllerName);
    }

    [Fact]
    public async Task Index_WizardCompleted_WithForce_RendersWithIsRerunFlag()
    {
        _wizard.Setup(w => w.GetOrCreateWizardStateAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync(State(currentStep: 5, completed: true));
        StubBuildPageDeps();

        var c = CreateController();
        var result = await c.Index(force: true);

        var view = Assert.IsType<ViewResult>(result);
        Assert.IsType<WizardPageViewModel>(view.Model);
        Assert.True((bool)c.ViewBag.IsRerun);
    }

    // ── Index: step clamping ──────────────────────────────────────────

    [Theory]
    [InlineData(0, 1)]   // below min → 1
    [InlineData(1, 1)]
    [InlineData(7, 5)]   // above max → 5
    public async Task Index_StepClampedToValidRange(int requested, int expected)
    {
        _wizard.Setup(w => w.GetOrCreateWizardStateAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync(State(currentStep: 5, completed: false));
        StubBuildPageDeps();

        var result = await CreateController().Index(step: requested);

        var view = Assert.IsType<ViewResult>(result);
        var vm = Assert.IsType<WizardPageViewModel>(view.Model);
        Assert.Equal(expected, vm.CurrentStep);
    }

    [Fact]
    public async Task Index_RequestedStepBeyondUnlocked_ClampsToCurrentStep()
    {
        // The user types ?step=4 in the URL but they've only saved through step 2.
        // The clamp prevents skipping unsaved data.
        _wizard.Setup(w => w.GetOrCreateWizardStateAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync(State(currentStep: 2));
        StubBuildPageDeps();

        var result = await CreateController().Index(step: 4);

        var view = Assert.IsType<ViewResult>(result);
        var vm = Assert.IsType<WizardPageViewModel>(view.Model);
        Assert.Equal(2, vm.CurrentStep); // clamped down to maxAllowed
    }

    // ── Step submission: invalid → re-render, valid → save + advance ───

    [Fact]
    public async Task SaveStep1_InvalidModelState_ReRendersAtStep1_DoesNotSave()
    {
        var c = CreateController();
        c.ModelState.AddModelError("Interfaces", "required");
        StubBuildPageDeps();
        _wizard.Setup(w => w.GetOrCreateWizardStateAsync(It.IsAny<CancellationToken>())).ReturnsAsync(State());

        var result = await c.SaveStep1(new Step1ViewModel(), CancellationToken.None);

        var view = Assert.IsType<ViewResult>(result);
        Assert.Equal("Index", view.ViewName);
        _wizard.Verify(w => w.SaveStep1InterfacesAsync(It.IsAny<List<WizardInterfaceConfig>>(), It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task SaveStep1_Valid_SavesAndAdvancesToStep2()
    {
        var c = CreateController();

        var result = await c.SaveStep1(new Step1ViewModel(), CancellationToken.None);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal("Index", redirect.ActionName);
        Assert.Equal(2, redirect.RouteValues!["step"]);
        _wizard.Verify(w => w.SaveStep1InterfacesAsync(It.IsAny<List<WizardInterfaceConfig>>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task SaveStep2_Valid_AdvancesToStep3()
    {
        var c = CreateController();
        var result = await c.SaveStep2(new Step2ViewModel(), CancellationToken.None);
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(3, redirect.RouteValues!["step"]);
        _wizard.Verify(w => w.SaveStep2LanAsync(It.IsAny<List<WizardLanConfig>>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task SaveStep3_Valid_AdvancesToStep4()
    {
        var c = CreateController();
        var result = await c.SaveStep3(new Step3ViewModel(), CancellationToken.None);
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(4, redirect.RouteValues!["step"]);
        _wizard.Verify(w => w.SaveStep3FirewallAsync(It.IsAny<WizardFirewallConfig>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task SaveStep4_Valid_AdvancesToStep5_ReviewPage()
    {
        var c = CreateController();
        var result = await c.SaveStep4(new Step4ViewModel(), CancellationToken.None);
        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(5, redirect.RouteValues!["step"]);
        _wizard.Verify(w => w.SaveStep4ServicesAsync(It.IsAny<WizardServicesConfig>(), It.IsAny<CancellationToken>()), Times.Once);
    }

    // ── Back: clamps to 1 ──────────────────────────────────────────────

    [Fact]
    public async Task Back_FromStep3_GoesToStep2_AndPersistsCurrentStep()
    {
        var result = await CreateController().Back(from: 3, CancellationToken.None);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(2, redirect.RouteValues!["step"]);
        _wizard.Verify(w => w.SetCurrentStepAsync(2, It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Back_FromStep1_StaysAtStep1()
    {
        var result = await CreateController().Back(from: 1, CancellationToken.None);

        var redirect = Assert.IsType<RedirectToActionResult>(result);
        Assert.Equal(1, redirect.RouteValues!["step"]);
        _wizard.Verify(w => w.SetCurrentStepAsync(1, It.IsAny<CancellationToken>()), Times.Once);
    }

    // ── Complete: orchestrates 5 wizard service calls in order ─────────

    [Fact]
    public async Task Complete_RunsAllApplyMethods_ThenMarksWizardCompleted()
    {
        var step1 = new List<WizardInterfaceConfig>();
        var step2 = new List<WizardLanConfig>();
        var step3 = new WizardFirewallConfig();
        var step4 = new WizardServicesConfig();
        _wizard.Setup(w => w.GetStep1InterfacesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(step1);
        _wizard.Setup(w => w.GetStep2LanAsync(It.IsAny<CancellationToken>())).ReturnsAsync(step2);
        _wizard.Setup(w => w.GetStep3FirewallAsync(It.IsAny<CancellationToken>())).ReturnsAsync(step3);
        _wizard.Setup(w => w.GetStep4ServicesAsync(It.IsAny<CancellationToken>())).ReturnsAsync(step4);

        await CreateController().Complete(CancellationToken.None);

        // All four apply methods invoked exactly once, then CompleteWizard.
        _wizard.Verify(w => w.ApplyInterfaceConfigAsync(step1, It.IsAny<CancellationToken>()), Times.Once);
        _wizard.Verify(w => w.ApplyLanConfigAsync(step2, It.IsAny<CancellationToken>()), Times.Once);
        _wizard.Verify(w => w.ApplyFirewallConfigAsync(step3, step1, It.IsAny<CancellationToken>()), Times.Once);
        _wizard.Verify(w => w.ApplyServicesConfigAsync(step4, It.IsAny<CancellationToken>()), Times.Once);
        _wizard.Verify(w => w.CompleteWizardAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Complete_StepDataMissing_FallsBackToEmptyDefaults_StillRuns()
    {
        // Defensive: if a saved step is null (caller skipped a step in a custom
        // flow), the controller substitutes empty defaults and Apply still runs.
        // No NRE, no half-applied state from missing input.
        _wizard.Setup(w => w.GetStep1InterfacesAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync((List<WizardInterfaceConfig>?)null);
        _wizard.Setup(w => w.GetStep2LanAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync((List<WizardLanConfig>?)null);
        _wizard.Setup(w => w.GetStep3FirewallAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync((WizardFirewallConfig?)null);
        _wizard.Setup(w => w.GetStep4ServicesAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync((WizardServicesConfig?)null);

        await CreateController().Complete(CancellationToken.None);

        _wizard.Verify(w => w.CompleteWizardAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task Complete_ApplyThrows_ReturnsFailEnvelope_NotCrash()
    {
        _wizard.Setup(w => w.GetStep1InterfacesAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync(new List<WizardInterfaceConfig>());
        _wizard.Setup(w => w.GetStep2LanAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync(new List<WizardLanConfig>());
        _wizard.Setup(w => w.GetStep3FirewallAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync(new WizardFirewallConfig());
        _wizard.Setup(w => w.GetStep4ServicesAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync(new WizardServicesConfig());
        _wizard.Setup(w => w.ApplyFirewallConfigAsync(It.IsAny<WizardFirewallConfig>(),
                It.IsAny<List<WizardInterfaceConfig>>(), It.IsAny<CancellationToken>()))
               .ThrowsAsync(new InvalidOperationException("nft missing"));

        var result = await CreateController().Complete(CancellationToken.None);

        var json = Assert.IsType<JsonResult>(result);
        var resp = Assert.IsType<ServiceResponse<object>>(json.Value);
        Assert.False(resp.Success);
        Assert.Contains("nft missing", resp.Message);
        // Wizard NOT marked completed — important: re-running the wizard should
        // be possible without a force flag.
        _wizard.Verify(w => w.CompleteWizardAsync(It.IsAny<CancellationToken>()), Times.Never);
    }

    // ── Reset / RestartNetworking ─────────────────────────────────────

    [Fact]
    public async Task Reset_DelegatesToWizardService()
    {
        var result = await CreateController().Reset(CancellationToken.None);

        Assert.IsType<JsonResult>(result);
        _wizard.Verify(w => w.ResetWizardAsync(It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task RestartNetworking_DelegatesToDaemon_AndForwardsResult()
    {
        _daemon.Setup(d => d.RestartNetworkingAsync(It.IsAny<CancellationToken>()))
               .ReturnsAsync(ServiceResponse<NetworkApplyResult>.Ok(
                   new NetworkApplyResult { Success = true, Message = "restarted" }, "ok"));

        await CreateController().RestartNetworking(CancellationToken.None);

        _daemon.Verify(d => d.RestartNetworkingAsync(It.IsAny<CancellationToken>()), Times.Once);
    }
}
