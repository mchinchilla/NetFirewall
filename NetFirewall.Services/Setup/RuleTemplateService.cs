using System.Net;
using Microsoft.Extensions.Logging;
using NetFirewall.Models.Firewall;
using NetFirewall.Models.Network;
using NetFirewall.Models.Setup;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;

namespace NetFirewall.Services.Setup;

/// <summary>
/// Compiles a <see cref="RuleTemplateSelection"/> into network objects + fw_*
/// rows. See <see cref="IRuleTemplateService"/> for the contract. The generator
/// stays "stupid": it only ever puts NetworkObject NAMES into address fields;
/// INetworkObjectResolver expands them to CIDRs at apply time.
/// </summary>
public sealed class RuleTemplateService : IRuleTemplateService
{
    private readonly IFirewallService _fw;
    private readonly INetworkObjectService _objects;
    private readonly IPolicyRoutingService _routing;
    private readonly ILogger<RuleTemplateService> _logger;

    public RuleTemplateService(
        IFirewallService fw,
        INetworkObjectService objects,
        IPolicyRoutingService routing,
        ILogger<RuleTemplateService> logger)
    {
        _fw = fw;
        _objects = objects;
        _routing = routing;
        _logger = logger;
    }

    public async Task<RuleTemplateResult> ApplyTemplateAsync(RuleTemplateSelection sel, CancellationToken ct = default)
    {
        if (!sel.IsValid())
            throw new ArgumentException($"Invalid template selection (base='{sel.Base}', port={sel.WebInterfacePort}).");

        var result = new RuleTemplateResult { Base = sel.Base };
        _logger.LogInformation("Applying rule template '{Base}' (nat={Nat}, multiWan={Mw})",
            sel.Base, sel.EnableNat, sel.EnableMultiWan);

        // Idempotency: wipe our own previously-generated rows first, so a re-apply
        // converges instead of duplicating. Hand-made rules are untouched.
        await ClearTemplateRulesAsync(ct);

        var interfaces = await _fw.GetInterfacesAsync(ct);
        var wans = interfaces.Where(i => string.Equals(i.Type, "WAN", StringComparison.OrdinalIgnoreCase) && i.Enabled).ToList();
        var lans = interfaces.Where(i => string.Equals(i.Type, "LAN", StringComparison.OrdinalIgnoreCase) && i.Enabled).ToList();

        if (wans.Count == 0) result.Notes.Add("No WAN interface assigned — WAN-facing rules were limited.");
        if (lans.Count == 0) result.Notes.Add("No LAN interface assigned — LAN-facing rules were skipped.");

        // 1) Network objects (reusable, referenced by name from the rules).
        result.NetworkObjectsCreated = await EnsureBaseObjectsAsync(lans, ct);

        // 2) Rules per base archetype + capabilities.
        int prio = await AddCommonInputRulesAsync(sel, result, 10, ct);

        switch (sel.Base)
        {
            case RuleTemplateBases.Gateway:
            case RuleTemplateBases.Router:
                prio = await AddForwardRulesAsync(sel, result, lans, prio, ct);
                if (sel.EnableNat && sel.Base == RuleTemplateBases.Gateway)
                    await AddNatRulesAsync(sel, result, wans, lans, ct);
                else if (sel.EnableNat && sel.Base == RuleTemplateBases.Router)
                    result.Notes.Add("NAT requested but base is 'router' (no-NAT) — masquerade was skipped.");
                break;

            case RuleTemplateBases.Bastion:
                // Input-only: no forward chain rules. The common input rules above
                // (established, loopback, mgmt) already form the posture.
                result.Notes.Add("Bastion base: no forwarding rules generated (input-only host).");
                break;
        }

        // 3) Multi-WAN policy routing (only meaningful with 2+ WANs).
        if (sel.EnableMultiWan)
            result.PolicyRoutingRows = await AddMultiWanAsync(wans, result, ct);

        // 4) Optional example port-forward (disabled — operator edits + enables).
        if (sel.SeedPortForwardExample && wans.Count > 0)
            await AddExamplePortForwardAsync(sel, result, wans[0], lans, ct);

        _logger.LogInformation("Template '{Base}' applied: {Filter} filter, {Nat} nat, {Pf} pf, {Obj} objects",
            sel.Base, result.FilterRules, result.NatRules, result.PortForwards, result.NetworkObjectsCreated);
        return result;
    }

    // ───────────────────────── network objects ─────────────────────────

    private async Task<int> EnsureBaseObjectsAsync(IReadOnlyList<FwInterface> lans, CancellationToken ct)
    {
        int created = 0;

        // RFC1918 — a group of the three private networks.
        created += await EnsureNetworkObjectAsync(
            RuleTemplateObjects.Rfc1918, NetworkObjectTypes.Group, "",
            "RFC1918 private ranges", ct,
            members:
            [
                ("RFC1918_10",     NetworkObjectTypes.Network, "10.0.0.0/8"),
                ("RFC1918_172",    NetworkObjectTypes.Network, "172.16.0.0/12"),
                ("RFC1918_192",    NetworkObjectTypes.Network, "192.168.0.0/16"),
            ],
            countCreated: c => created += c);

        // BOGONS — RFC1918 + loopback/link-local/multicast that must not arrive on WAN.
        created += await EnsureNetworkObjectAsync(
            RuleTemplateObjects.Bogons, NetworkObjectTypes.Group, "",
            "Bogon/martian sources (never valid inbound on a WAN)", ct,
            members:
            [
                ("BOGON_LOOPBACK",   NetworkObjectTypes.Network, "127.0.0.0/8"),
                ("BOGON_LINKLOCAL",  NetworkObjectTypes.Network, "169.254.0.0/16"),
                ("BOGON_MULTICAST",  NetworkObjectTypes.Network, "224.0.0.0/4"),
                ("BOGON_RESERVED",   NetworkObjectTypes.Network, "240.0.0.0/4"),
                ("RFC1918_10",       NetworkObjectTypes.Network, "10.0.0.0/8"),
                ("RFC1918_172",      NetworkObjectTypes.Network, "172.16.0.0/12"),
                ("RFC1918_192",      NetworkObjectTypes.Network, "192.168.0.0/16"),
            ],
            countCreated: c => created += c);

        // LAN_NETWORKS — group of every assigned LAN's CIDR. Rebuilt from the
        // current interface assignments each run.
        var lanMembers = new List<(string, string, string)>();
        int idx = 1;
        foreach (var lan in lans)
        {
            var cidr = ToCidr(lan.IpAddress, lan.SubnetMask);
            if (cidr is null) continue;
            lanMembers.Add(($"LAN_{lan.Name}".ToUpperInvariant(), NetworkObjectTypes.Network, cidr));
            idx++;
        }
        created += await EnsureNetworkObjectAsync(
            RuleTemplateObjects.LanNetworks, NetworkObjectTypes.Group, "",
            "All assigned LAN networks (template-managed)", ct,
            members: lanMembers,
            countCreated: c => created += c);

        // MGMT_SOURCES — starts as LAN_NETWORKS; operator narrows it to admin hosts.
        // We model it as a group whose only member is LAN_NETWORKS so the default
        // is "manage from the LAN" and tightening it is a one-object edit.
        created += await EnsureGroupOfExistingAsync(
            RuleTemplateObjects.MgmtSources,
            "Where management (SSH/web UI) is allowed from — defaults to the LAN; narrow this to your admin hosts",
            [RuleTemplateObjects.LanNetworks], ct, c => created += c);

        return created;
    }

    /// <summary>
    /// Create-or-reuse a network object by name. For a group, ensures each member
    /// leaf object exists and wires up membership. Returns 1 if the top object was
    /// newly created (0 if it already existed); leaf creations are reported via
    /// <paramref name="countCreated"/>.
    /// </summary>
    private async Task<int> EnsureNetworkObjectAsync(
        string name, string type, string value, string description,
        CancellationToken ct,
        IReadOnlyList<(string Name, string Type, string Value)>? members = null,
        Action<int>? countCreated = null)
    {
        int leafCreated = 0;
        var childIds = new List<Guid>();

        if (members is not null)
        {
            foreach (var (mName, mType, mValue) in members)
            {
                var existing = await _objects.GetByNameAsync(mName, ct: ct);
                if (existing is null)
                {
                    var leaf = await _objects.CreateAsync(new NetworkObject
                    {
                        Name = mName, Type = mType, Value = mValue,
                        Description = $"{RuleTemplateTags.ObjectPrefix} {description} member",
                    }, ct);
                    childIds.Add(leaf.Id);
                    leafCreated++;
                }
                else
                {
                    childIds.Add(existing.Id);
                }
            }
        }

        var top = await _objects.GetByNameAsync(name, ct: ct);
        int topCreated = 0;
        if (top is null)
        {
            top = await _objects.CreateAsync(new NetworkObject
            {
                Name = name, Type = type, Value = value,
                Description = $"{RuleTemplateTags.ObjectPrefix} {description}",
            }, ct);
            topCreated = 1;
        }

        if (type == NetworkObjectTypes.Group)
            await _objects.SetGroupMembersAsync(top.Id, childIds, ct);

        countCreated?.Invoke(leafCreated);
        return topCreated;
    }

    /// <summary>Ensure a group whose members are other EXISTING named objects.</summary>
    private async Task<int> EnsureGroupOfExistingAsync(
        string name, string description, IReadOnlyList<string> memberNames,
        CancellationToken ct, Action<int> _)
    {
        var childIds = new List<Guid>();
        foreach (var mn in memberNames)
        {
            var m = await _objects.GetByNameAsync(mn, ct: ct);
            if (m is not null) childIds.Add(m.Id);
        }

        var top = await _objects.GetByNameAsync(name, ct: ct);
        int created = 0;
        if (top is null)
        {
            top = await _objects.CreateAsync(new NetworkObject
            {
                Name = name, Type = NetworkObjectTypes.Group, Value = "",
                Description = $"{RuleTemplateTags.ObjectPrefix} {description}",
            }, ct);
            created = 1;
        }
        await _objects.SetGroupMembersAsync(top.Id, childIds, ct);
        return created;
    }

    // ───────────────────────── filter rules ─────────────────────────

    private async Task<int> AddCommonInputRulesAsync(RuleTemplateSelection sel, RuleTemplateResult r, int prio, CancellationToken ct)
    {
        // established/related — the backbone of a stateful default-deny posture.
        await CreateFilterAsync(new FwFilterRule
        {
            Chain = "input", Action = "accept",
            ConnectionState = ["established", "related"],
            Priority = prio++,
        }, sel.Base, "Allow established/related", r, ct);

        // loopback
        await CreateFilterAsync(new FwFilterRule
        {
            Chain = "input", Action = "accept",
            SourceAddresses = ["127.0.0.0/8"],
            Priority = prio++,
        }, sel.Base, "Allow loopback", r, ct);

        // drop invalid (default-deny hygiene)
        await CreateFilterAsync(new FwFilterRule
        {
            Chain = "input", Action = "drop",
            ConnectionState = ["invalid"],
            Priority = prio++,
        }, sel.Base, "Drop invalid", r, ct);

        if (sel.AllowIcmp)
            await CreateFilterAsync(new FwFilterRule
            {
                Chain = "input", Action = "accept", Protocol = "icmp",
                Priority = prio++,
            }, sel.Base, "Allow ICMP ping", r, ct);

        if (sel.AllowManagement)
        {
            // SSH + web UI, only from the management sources object.
            await CreateFilterAsync(new FwFilterRule
            {
                Chain = "input", Action = "accept", Protocol = "tcp",
                SourceAddresses = [RuleTemplateObjects.MgmtSources],
                DestinationPorts = ["22"],
                ConnectionState = ["new"],
                Priority = prio++,
            }, sel.Base, "Allow SSH from management", r, ct);

            await CreateFilterAsync(new FwFilterRule
            {
                Chain = "input", Action = "accept", Protocol = "tcp",
                SourceAddresses = [RuleTemplateObjects.MgmtSources],
                DestinationPorts = [sel.WebInterfacePort.ToString()],
                ConnectionState = ["new"],
                Priority = prio++,
            }, sel.Base, $"Allow web UI ({sel.WebInterfacePort}) from management", r, ct);
        }

        if (sel.AllowDns)
            await CreateFilterAsync(new FwFilterRule
            {
                Chain = "input", Action = "accept", Protocol = "udp",
                SourceAddresses = [RuleTemplateObjects.LanNetworks],
                DestinationPorts = ["53"],
                Priority = prio++,
            }, sel.Base, "Allow DNS from LAN", r, ct);

        if (sel.AllowDhcp)
            await CreateFilterAsync(new FwFilterRule
            {
                Chain = "input", Action = "accept", Protocol = "udp",
                DestinationPorts = ["67", "68"],
                Priority = prio++,
            }, sel.Base, "Allow DHCP", r, ct);

        return prio;
    }

    private async Task<int> AddForwardRulesAsync(RuleTemplateSelection sel, RuleTemplateResult r, IReadOnlyList<FwInterface> lans, int prio, CancellationToken ct)
    {
        // forward: established/related back to LAN.
        await CreateFilterAsync(new FwFilterRule
        {
            Chain = "forward", Action = "accept",
            ConnectionState = ["established", "related"],
            Priority = prio++,
        }, sel.Base, "Forward established/related", r, ct);

        // forward: LAN networks → anywhere (new).
        await CreateFilterAsync(new FwFilterRule
        {
            Chain = "forward", Action = "accept",
            SourceAddresses = [RuleTemplateObjects.LanNetworks],
            ConnectionState = ["new", "established", "related"],
            Priority = prio++,
        }, sel.Base, "Forward LAN outbound", r, ct);

        // default-deny forward (explicit drop at the end).
        await CreateFilterAsync(new FwFilterRule
        {
            Chain = "forward", Action = "drop",
            Priority = 9000,
        }, sel.Base, "Default-deny forward", r, ct);

        return prio;
    }

    private async Task AddNatRulesAsync(RuleTemplateSelection sel, RuleTemplateResult r,
        IReadOnlyList<FwInterface> wans, IReadOnlyList<FwInterface> lans, CancellationToken ct)
    {
        // fw_nat_rules.source_network is a Postgres `cidr` column — it does NOT
        // accept a network-object NAME (unlike the text[] address fields on filter
        // rules). So NAT masquerade rows must carry literal LAN CIDRs. We emit one
        // rule per (WAN, LAN-CIDR) pair. (The object-by-name indirection still
        // applies everywhere the column is text[].)
        var lanCidrs = lans
            .Select(l => ToCidr(l.IpAddress, l.SubnetMask))
            .Where(c => c is not null).Select(c => c!)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (lanCidrs.Count == 0)
        {
            r.Notes.Add("NAT skipped — no LAN network to masquerade.");
            return;
        }

        foreach (var wan in wans)
        {
            foreach (var cidr in lanCidrs)
            {
                var nat = new FwNatRule
                {
                    Type = "masquerade",
                    Description = RuleTemplateTags.Rule(sel.Base, $"Masquerade {cidr} via {wan.Name}"),
                    SourceNetwork = cidr,
                    OutputInterfaceId = wan.Id,
                    Enabled = true,
                    Priority = 100,
                };
                await _fw.CreateNatRuleAsync(nat, ct);
                r.NatRules++;
            }
        }
    }

    private async Task<int> AddMultiWanAsync(IReadOnlyList<FwInterface> wans, RuleTemplateResult r, CancellationToken ct)
    {
        if (wans.Count < 2)
        {
            r.Notes.Add($"Multi-WAN requested but only {wans.Count} WAN assigned — policy routing skipped.");
            return 0;
        }

        int rows = 0;
        int markBase = 0x100; // 0x100, 0x200, … per WAN (matches the tekium seed convention).
        int n = 1;
        foreach (var wan in wans)
        {
            var tableName = $"wan{n}";
            var tableId = 200 + n; // 201, 202, …  (avoids clobbering reserved 200/202 if present)
            await _routing.EnsureRouteTableAsync(tableId, tableName,
                $"{RuleTemplateTags.Prefix} {wan.Name} policy routing table", ct);
            long fwmark = markBase * n; // 0x100, 0x200, …
            await _routing.EnsurePolicyRuleAsync(fwmark, tableName, 100 + n,
                $"{RuleTemplateTags.Prefix} mark 0x{fwmark:X} → {tableName} ({wan.Name})", ct);
            rows += 2;
            n++;
        }
        r.Notes.Add($"Multi-WAN: created policy routing for {wans.Count} WANs. " +
                    "Assign per-LAN egress marks in Firewall → Policy routing to balance/pin traffic.");
        return rows;
    }

    private async Task AddExamplePortForwardAsync(RuleTemplateSelection sel, RuleTemplateResult r, FwInterface wan, IReadOnlyList<FwInterface> lans, CancellationToken ct)
    {
        // A disabled, obviously-placeholder example the operator edits then enables.
        var internalIp = lans.Count > 0 && lans[0].IpAddress is not null
            ? lans[0].IpAddress!  // first LAN's own IP as a stand-in target
            : IPAddress.Parse("192.168.1.10");

        var pf = new FwPortForward
        {
            Description = RuleTemplateTags.Rule(sel.Base, "EXAMPLE port-forward (disabled — edit me)"),
            Protocol = "tcp",
            InterfaceId = wan.Id,
            ExternalPortStart = 8080,
            InternalIp = internalIp,
            InternalPort = 80,
            Enabled = false,
            Priority = 100,
        };
        await _fw.CreatePortForwardAsync(pf, ct);
        r.PortForwards++;
    }

    // ───────────────────────── idempotency / teardown ─────────────────────────

    public async Task<int> ClearTemplateRulesAsync(CancellationToken ct = default)
    {
        int removed = 0;

        foreach (var fr in await _fw.GetFilterRulesAsync(null, ct))
            if (RuleTemplateTags.IsTemplate(fr.Description) && await _fw.DeleteFilterRuleAsync(fr.Id, ct))
                removed++;

        foreach (var nr in await _fw.GetNatRulesAsync(ct))
            if (RuleTemplateTags.IsTemplate(nr.Description) && await _fw.DeleteNatRuleAsync(nr.Id, ct))
                removed++;

        foreach (var pf in await _fw.GetPortForwardsAsync(ct))
            if (RuleTemplateTags.IsTemplate(pf.Description) && await _fw.DeletePortForwardAsync(pf.Id, ct))
                removed++;

        // Note: template-owned network objects (LAN_NETWORKS etc.) are NOT deleted
        // here — they're reusable and may be referenced by the operator's own
        // rules. Re-applying a template rebuilds their membership in place.
        return removed;
    }

    // ───────────────────────── helpers ─────────────────────────

    private async Task CreateFilterAsync(FwFilterRule rule, string baseName, string what, RuleTemplateResult r, CancellationToken ct)
    {
        rule.Description = RuleTemplateTags.Rule(baseName, what);
        rule.Enabled = true;
        await _fw.CreateFilterRuleAsync(rule, ct);
        r.FilterRules++;
    }

    private static string? ToCidr(IPAddress? ip, IPAddress? mask)
    {
        if (ip is null || mask is null) return null;
        var mb = mask.GetAddressBytes();
        int bits = mb.Sum(b => System.Numerics.BitOperations.PopCount((uint)b));
        var ib = ip.GetAddressBytes();
        if (ib.Length != mb.Length) return null;
        for (int i = 0; i < ib.Length; i++) ib[i] &= mb[i];
        return $"{new IPAddress(ib)}/{bits}";
    }
}
