using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Services.Network;
using NetFirewall.Services.Setup;
using NetFirewall.Web.Daemon;
using NetFirewall.Web.Filters;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Setup;

namespace NetFirewall.Web.Controllers;

/// <summary>
/// Multi-step initial-setup wizard. Honors project rule #10: every
/// state read / write goes through <see cref="ISetupWizardService"/> —
/// the controller never touches Postgres or JSON serialization itself.
/// </summary>
[Authorize(Roles = UserRoles.Admin)]
[Route("/setup/wizard")]
public sealed class SetupWizardController : Controller
{
    private readonly ISetupWizardService _wizard;
    private readonly IDaemonClient _daemon;
    private readonly INetworkConfigResolver _resolver;
    private readonly ILogger<SetupWizardController> _logger;

    public SetupWizardController(
        ISetupWizardService wizard,
        IDaemonClient daemon,
        INetworkConfigResolver resolver,
        ILogger<SetupWizardController> logger)
    {
        _wizard = wizard;
        _daemon = daemon;
        _resolver = resolver;
        _logger = logger;
    }

    // ----- entry point -----

    [HttpGet("")]
    public async Task<IActionResult> Index(
        [FromQuery] int? step = null,
        [FromQuery] bool force = false,
        CancellationToken ct = default)
    {
        var state = await _wizard.GetOrCreateWizardStateAsync(ct);
        if (state.IsCompleted && !force)
            return RedirectToAction("Index", "Home");

        // ?step=N lets the user jump back to an already-visited step (the
        // Stepper renders previous steps as links). Forward jumps are clamped
        // to whatever the wizard service has actually unlocked so the user
        // can't skip past unsaved data.
        var requested = step ?? state.CurrentStep;
        var maxAllowed = Math.Max(state.CurrentStep, 1);
        var resolved = Math.Clamp(requested, 1, Math.Min(5, maxAllowed));

        ViewBag.IsRerun = state.IsCompleted && force;
        var vm = await BuildPageAsync(resolved, ct);
        return View(vm);
    }

    // ----- step submissions (each saves + advances) -----

    [HttpPost("step/1"), ValidateAntiForgeryToken]
    public async Task<IActionResult> SaveStep1([FromForm] Step1ViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid) return await RenderAtAsync(1, ct, form);
        await _wizard.SaveStep1InterfacesAsync(form.ToServiceModel(), ct);
        return RedirectToStep(2);
    }

    [HttpPost("step/2"), ValidateAntiForgeryToken]
    public async Task<IActionResult> SaveStep2([FromForm] Step2ViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid) return await RenderAtAsync(2, ct, step2: form);
        await _wizard.SaveStep2LanAsync(form.ToServiceModel(), ct);
        return RedirectToStep(3);
    }

    [HttpPost("step/3"), ValidateAntiForgeryToken]
    public async Task<IActionResult> SaveStep3([FromForm] Step3ViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid) return await RenderAtAsync(3, ct, step3: form);
        await _wizard.SaveStep3FirewallAsync(form.ToServiceModel(), ct);
        return RedirectToStep(4);
    }

    [HttpPost("step/4"), ValidateAntiForgeryToken]
    public async Task<IActionResult> SaveStep4([FromForm] Step4ViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid) return await RenderAtAsync(4, ct, step4: form);
        await _wizard.SaveStep4ServicesAsync(form.ToServiceModel(), ct);
        return RedirectToStep(5);
    }

    // ----- back / jump -----

    [HttpPost("back/{from:int}"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Back(int from, CancellationToken ct)
    {
        var target = Math.Max(1, from - 1);
        await _wizard.SetCurrentStepAsync(target, ct);
        return RedirectToStep(target);
    }

    // ----- finalize: apply each step then mark completed -----

    [HttpPost("complete"), ValidateAntiForgeryToken, RequireElevated]
    public async Task<IActionResult> Complete(CancellationToken ct)
    {
        try
        {
            var step1 = await _wizard.GetStep1InterfacesAsync(ct) ?? new();
            var step2 = await _wizard.GetStep2LanAsync(ct) ?? new();
            var step3 = await _wizard.GetStep3FirewallAsync(ct) ?? new();
            var step4 = await _wizard.GetStep4ServicesAsync(ct) ?? new();

            await _wizard.ApplyInterfaceConfigAsync(step1, ct);
            await _wizard.ApplyLanConfigAsync(step2, ct);
            await _wizard.ApplyFirewallConfigAsync(step3, step1, ct);
            await _wizard.ApplyServicesConfigAsync(step4, ct);
            await _wizard.CompleteWizardAsync(ct);

            return this.ToHtmxResponse(ServiceResponse<object>.Ok(new { }, "Setup applied. Restart networking to bring it live."));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Wizard apply failed");
            return this.ToHtmxResponse(ServiceResponse<object>.Fail($"Apply failed: {ex.Message}"));
        }
    }

    [HttpPost("restart-networking"), ValidateAntiForgeryToken, RequireElevated]
    public async Task<IActionResult> RestartNetworking(CancellationToken ct)
    {
        var envelope = await _daemon.RestartNetworkingAsync(ct);
        return this.ToHtmxResponse(envelope);
    }

    [HttpPost("reset"), ValidateAntiForgeryToken, RequireElevated]
    public async Task<IActionResult> Reset(CancellationToken ct)
    {
        await _wizard.ResetWizardAsync(ct);
        return this.ToHtmxResponse(ServiceResponse<object>.Ok(new { }, "Wizard reset."));
    }

    // ----- helpers (composition only — no IO here) -----

    private RedirectToActionResult RedirectToStep(int step) =>
        RedirectToAction(nameof(Index), new { step });

    /// <summary>Re-render the page at a given step preserving form input that failed validation.</summary>
    private async Task<IActionResult> RenderAtAsync(
        int step, CancellationToken ct,
        Step1ViewModel? step1 = null,
        Step2ViewModel? step2 = null,
        Step3ViewModel? step3 = null,
        Step4ViewModel? step4 = null)
    {
        var vm = await BuildPageAsync(step, ct, step1, step2, step3, step4);
        return View(nameof(Index), vm);
    }

    private async Task<WizardPageViewModel> BuildPageAsync(
        int step, CancellationToken ct,
        Step1ViewModel? overrideStep1 = null,
        Step2ViewModel? overrideStep2 = null,
        Step3ViewModel? overrideStep3 = null,
        Step4ViewModel? overrideStep4 = null)
    {
        var detected = await _wizard.DetectNetworkInterfacesAsync(ct);
        var savedStep1 = await _wizard.GetStep1InterfacesAsync(ct);
        var savedStep2 = await _wizard.GetStep2LanAsync(ct);
        var savedStep3 = await _wizard.GetStep3FirewallAsync(ct);
        var savedStep4 = await _wizard.GetStep4ServicesAsync(ct);
        var state = await _wizard.GetOrCreateWizardStateAsync(ct);

        var step1 = overrideStep1 ?? savedStep1.ToViewModel(detected);
        var step2 = overrideStep2 ?? savedStep2.ToViewModel(step1);

        return new WizardPageViewModel
        {
            CurrentStep = Math.Clamp(step, 1, 5),
            MaxUnlockedStep = Math.Clamp(state.CurrentStep, 1, 5),
            IsCompleted = state.IsCompleted,
            Detected = detected,
            Step1 = step1,
            Step2 = step2,
            Step3 = overrideStep3 ?? savedStep3.ToViewModel(),
            Step4 = overrideStep4 ?? savedStep4.ToViewModel()
        };
    }
}
