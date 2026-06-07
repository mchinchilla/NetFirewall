using NetFirewall.Models.Setup;

namespace NetFirewall.Services.Setup;

/// <summary>
/// Generates a starting firewall rule set from a wizard <see cref="RuleTemplateSelection"/>.
///
/// Contract:
///  * Writes ONLY to the database (network objects + fw_* rows). It does NOT push
///    anything to the kernel — the operator reviews the rules and clicks Apply
///    (the existing DB→Apply flow). This is deliberate: a mis-parameterised rule
///    set should never lock the operator out on generation.
///  * Rules reference NetworkObjects by name (LAN_NETWORKS, BOGONS, …), never raw
///    CIDRs — the value lives in one editable place and INetworkObjectResolver
///    expands it at apply time.
///  * Idempotent: every generated row is tagged (RuleTemplateTags). Re-applying a
///    template removes only its own previously-generated rows, never the
///    operator's hand-made rules.
/// </summary>
public interface IRuleTemplateService
{
    /// <summary>
    /// Generate the network objects + fw_* rows for <paramref name="selection"/>,
    /// parameterised by the WAN/LAN interfaces already assigned (read from
    /// fw_interfaces). Returns a summary of what was created so the UI can report it.
    /// </summary>
    Task<RuleTemplateResult> ApplyTemplateAsync(RuleTemplateSelection selection, CancellationToken ct = default);

    /// <summary>
    /// Remove every row a previous template run created (matched by tag), across
    /// filter/nat/port-forward/mangle + the template-owned network objects.
    /// Leaves the operator's own rules untouched. Used before re-applying, and by
    /// a "clear template rules" action.
    /// </summary>
    Task<int> ClearTemplateRulesAsync(CancellationToken ct = default);
}

/// <summary>What a template run produced — surfaced to the UI as user feedback.</summary>
public sealed class RuleTemplateResult
{
    public string Base { get; set; } = string.Empty;
    public int NetworkObjectsCreated { get; set; }
    public int FilterRules { get; set; }
    public int NatRules { get; set; }
    public int PortForwards { get; set; }
    public int PolicyRoutingRows { get; set; }

    /// <summary>Human notes (e.g. "Multi-WAN skipped — only one WAN assigned").</summary>
    public List<string> Notes { get; set; } = [];

    public int TotalRules => FilterRules + NatRules + PortForwards;
}
