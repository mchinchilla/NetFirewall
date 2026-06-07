using System.ComponentModel.DataAnnotations;
using NetFirewall.Models.Setup;

namespace NetFirewall.Web.Models.Setup;

/// <summary>
/// Form binding for the wizard's "starting rule set" picker. Mirrors
/// <see cref="RuleTemplateSelection"/> with web-side validation (rule #4:
/// validate on both sides). Maps to the service selection via ToSelection().
/// </summary>
public sealed class RuleTemplateForm
{
    [Required]
    public string Base { get; set; } = RuleTemplateBases.Gateway;

    public bool EnableNat { get; set; } = true;
    public bool EnableMultiWan { get; set; }
    public bool AllowManagement { get; set; } = true;

    [Range(1, 65535, ErrorMessage = "Web UI port must be 1-65535.")]
    public int WebInterfacePort { get; set; } = 443;

    public bool AllowIcmp { get; set; } = true;
    public bool AllowDhcp { get; set; } = true;
    public bool AllowDns { get; set; } = true;
    public bool SeedPortForwardExample { get; set; }

    public RuleTemplateSelection ToSelection() => new()
    {
        Base = Base,
        EnableNat = EnableNat,
        EnableMultiWan = EnableMultiWan,
        AllowManagement = AllowManagement,
        WebInterfacePort = WebInterfacePort,
        AllowIcmp = AllowIcmp,
        AllowDhcp = AllowDhcp,
        AllowDns = AllowDns,
        SeedPortForwardExample = SeedPortForwardExample,
    };
}
