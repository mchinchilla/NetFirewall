namespace NetFirewall.Models.Setup;

/// <summary>
/// Operator's choice of a starting rule set in the setup wizard. A base
/// archetype defines the security posture; orthogonal capability toggles layer
/// on top (NAT, multi-WAN, management access, …). The generator
/// (IRuleTemplateService) compiles this into network objects + fw_* rows — it
/// never invents CIDRs: rules reference named NetworkObjects so the values are
/// editable in one place afterward.
///
/// All generated rows carry a description tag (<see cref="RuleTemplateTags"/>)
/// so re-applying a template is idempotent (delete-then-insert by tag) without
/// touching the operator's hand-made rules.
/// </summary>
public sealed class RuleTemplateSelection
{
    /// <summary>One of <see cref="RuleTemplateBases"/>.</summary>
    public string Base { get; set; } = RuleTemplateBases.Gateway;

    /// <summary>Masquerade LAN→WAN (gateway default on; transparent router off).</summary>
    public bool EnableNat { get; set; } = true;

    /// <summary>Policy routing + per-WAN marks + health monitoring for 2+ WANs.</summary>
    public bool EnableMultiWan { get; set; }

    /// <summary>Open SSH (22) + the web UI port to the management sources.</summary>
    public bool AllowManagement { get; set; } = true;

    /// <summary>Web UI port opened when <see cref="AllowManagement"/> is set.</summary>
    public int WebInterfacePort { get; set; } = 443;

    /// <summary>Allow ICMP echo (ping) to the firewall.</summary>
    public bool AllowIcmp { get; set; } = true;

    /// <summary>Permit DHCP (udp/67-68) on LAN interfaces (firewall serves DHCP).</summary>
    public bool AllowDhcp { get; set; } = true;

    /// <summary>Permit DNS (udp/tcp 53) to the firewall from LAN (resolver).</summary>
    public bool AllowDns { get; set; } = true;

    /// <summary>Seed a disabled example port-forward the operator can edit/enable.</summary>
    public bool SeedPortForwardExample { get; set; }

    public bool IsValid() => RuleTemplateBases.IsValid(Base) && WebInterfacePort is > 0 and <= 65535;
}

/// <summary>The base archetypes. Each sets a different default-deny shape.</summary>
public static class RuleTemplateBases
{
    /// <summary>NAT gateway: LAN→WAN forward, masquerade, default-deny WAN input.</summary>
    public const string Gateway = "gateway";

    /// <summary>Transparent router: routes between segments, NO NAT, default-deny WAN.</summary>
    public const string Router = "router";

    /// <summary>Bastion: input-only control for a single published host/service, no forward.</summary>
    public const string Bastion = "bastion";

    public static readonly string[] All = [Gateway, Router, Bastion];

    public static bool IsValid(string b) => Array.IndexOf(All, b) >= 0;

    public static string Label(string b) => b switch
    {
        Gateway => "Internet gateway (NAT)",
        Router  => "Transparent router (no NAT)",
        Bastion => "Bastion / single host",
        _       => b,
    };

    public static string Describe(string b) => b switch
    {
        Gateway => "LAN devices reach the internet through this box (masquerade). WAN is closed except what you open. The common home/SOHO firewall.",
        Router  => "Routes traffic between network segments without NAT. Use when another device does NAT, or for internal segmentation.",
        Bastion => "Locks down to a single published host/service — input-only, no forwarding. For a hardened jump host or appliance.",
        _       => "",
    };
}

/// <summary>
/// Description-tag prefixes stamped on every generated row so a template can be
/// re-applied idempotently (delete rows matching the tag, then re-insert) and so
/// the UI can show "this rule came from the &lt;X&gt; template".
/// </summary>
public static class RuleTemplateTags
{
    /// <summary>Prefix on every template-generated fw_* row's description.</summary>
    public const string Prefix = "[tpl]";

    /// <summary>Prefix on every template-generated network object's description.</summary>
    public const string ObjectPrefix = "[tpl-obj]";

    /// <summary>Build the description for a generated rule: "[tpl] gateway: Allow SSH".</summary>
    public static string Rule(string baseName, string what) => $"{Prefix} {baseName}: {what}";

    /// <summary>True if a description belongs to a template-generated row.</summary>
    public static bool IsTemplate(string? description) =>
        description is not null && description.StartsWith(Prefix, StringComparison.Ordinal);
}

/// <summary>Canonical names of the network objects a template creates/uses.</summary>
public static class RuleTemplateObjects
{
    /// <summary>Group of every assigned LAN network — rules reference this, not raw CIDRs.</summary>
    public const string LanNetworks = "LAN_NETWORKS";

    /// <summary>RFC1918 private ranges (10/8, 172.16/12, 192.168/16).</summary>
    public const string Rfc1918 = "RFC1918";

    /// <summary>Bogon / martian sources that must never arrive on a WAN.</summary>
    public const string Bogons = "BOGONS";

    /// <summary>Management source hosts/networks (starts as the LAN; operator narrows it).</summary>
    public const string MgmtSources = "MGMT_SOURCES";
}
