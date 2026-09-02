using System.Net.NetworkInformation;
using NetFirewall.Models.Dhcp;
using NetFirewall.Models.Firewall;

namespace NetFirewall.Web.Models;

/// <summary>Pure mapping from domain rows to dashboard/monitoring panel VMs.</summary>
public static class DashboardPanels
{
    public static RecentLeasesViewModel FromLeases(IReadOnlyList<DhcpLease> leases, int take, string? manageUrl)
    {
        var now = DateTime.UtcNow;
        var active = leases.Where(l => l.EndTime > now).ToList();
        var rows = active
            .OrderByDescending(l => l.StartTime)
            .Take(take)
            .Select(l => new RecentLeaseRow
            {
                Ip = l.IpAddress.ToString(),
                Mac = FormatMac(l.MacAddress),
                Hostname = l.Hostname,
                StartUtc = l.StartTime,
                EndUtc = l.EndTime,
            })
            .ToList();
        return new RecentLeasesViewModel
        {
            Rows = rows,
            TotalActive = active.Count,
            ManageUrl = manageUrl,
        };
    }

    public static PortForwardsSummaryViewModel FromForwards(
        IReadOnlyList<FwPortForward> forwards,
        IReadOnlyList<FwInterface> ifaces,
        int take,
        string? manageUrl)
    {
        var names = ifaces.ToDictionary(i => i.Id, i => i.Name);
        var enabled = forwards.Where(f => f.Enabled).ToList();
        var rows = enabled
            .OrderBy(f => f.Priority)
            .Take(take)
            .Select(f =>
            {
                var ext = f.ExternalPortEnd is { } end && end > f.ExternalPortStart
                    ? $"{f.ExternalPortStart}-{end}"
                    : f.ExternalPortStart.ToString();
                var iface = f.InterfaceId is { } id && names.TryGetValue(id, out var n) ? n : "any";
                return new PortForwardSummaryRow
                {
                    External = $"{ext}/{f.Protocol}",
                    Internal = $"{f.InternalIp}:{f.InternalPort}",
                    Iface = iface,
                    Description = f.Description,
                    Enabled = f.Enabled,
                };
            })
            .ToList();
        return new PortForwardsSummaryViewModel
        {
            Rows = rows,
            TotalEnabled = enabled.Count,
            Total = forwards.Count,
            ManageUrl = manageUrl,
        };
    }

    public static DropRulesViewModel FromFilters(IReadOnlyList<FwFilterRule> rules, int take, string? manageUrl)
    {
        var live = rules
            .Where(r => r.Enabled && (r.Action is "drop" or "reject"))
            .OrderBy(r => r.Chain)
            .ThenBy(r => r.Priority)
            .ToList();
        var rows = live.Take(take).Select(r => new DropRuleRow
        {
            Chain = r.Chain,
            Action = r.Action,
            Description = string.IsNullOrWhiteSpace(r.Description) ? null : r.Description,
            Match = MatchSummary(r),
        }).ToList();
        return new DropRulesViewModel
        {
            Rows = rows,
            TotalLive = live.Count,
            ManageUrl = manageUrl,
        };
    }

    public static ApplyStatusViewModel FromPending(IReadOnlyList<PendingApplySummary> pending, string? applyUrl)
        => new() { Items = pending, ApplyUrl = applyUrl };

    public static RecentAuditViewModel FromAudit(IReadOnlyList<FwAuditLog> entries, string? manageUrl)
        => new() { Entries = entries, ManageUrl = manageUrl };

    public static string MatchSummary(FwFilterRule r)
    {
        var parts = new List<string>(4);
        if (!string.IsNullOrEmpty(r.Protocol)) parts.Add(r.Protocol);
        if (r.SourceAddresses is { Length: > 0 }) parts.Add("src " + string.Join(",", r.SourceAddresses));
        if (r.DestinationAddresses is { Length: > 0 }) parts.Add("dst " + string.Join(",", r.DestinationAddresses));
        if (r.DestinationPorts is { Length: > 0 }) parts.Add(":" + string.Join(",", r.DestinationPorts));
        return parts.Count == 0 ? "any" : string.Join(" · ", parts);
    }

    public static string FormatMac(PhysicalAddress mac)
    {
        var raw = mac.ToString();
        if (raw.Length != 12) return raw;
        return string.Join(":", Enumerable.Range(0, 6).Select(i => raw.Substring(i * 2, 2).ToLowerInvariant()));
    }

    public static string Ago(DateTime utc)
    {
        var d = DateTime.UtcNow - DateTime.SpecifyKind(utc, DateTimeKind.Utc);
        if (d < TimeSpan.Zero) d = TimeSpan.Zero;
        if (d.TotalSeconds < 60) return $"{(int)d.TotalSeconds}s ago";
        if (d.TotalMinutes < 60) return $"{(int)d.TotalMinutes}m ago";
        if (d.TotalHours < 24) return $"{(int)d.TotalHours}h ago";
        return $"{(int)d.TotalDays}d ago";
    }

    public static string TableLabel(string name) =>
        name.StartsWith("fw_", StringComparison.Ordinal) ? name[3..].Replace('_', ' ') : name.Replace('_', ' ');
}

public sealed class RecentLeasesViewModel
{
    public IReadOnlyList<RecentLeaseRow> Rows { get; init; } = [];
    public int TotalActive { get; init; }
    public string? ManageUrl { get; init; }
}

public sealed class RecentLeaseRow
{
    public required string Ip { get; init; }
    public required string Mac { get; init; }
    public string? Hostname { get; init; }
    public DateTime StartUtc { get; init; }
    public DateTime EndUtc { get; init; }
}

public sealed class ApplyStatusViewModel
{
    public IReadOnlyList<PendingApplySummary> Items { get; init; } = [];
    public string? ApplyUrl { get; init; }
    public bool HasPending => Items.Any(i => i.HasPending);
    public DateTime? LastAppliedAt => Items
        .Select(i => i.LastAppliedAt)
        .Where(t => t.HasValue)
        .OrderByDescending(t => t)
        .FirstOrDefault();
}

public sealed class RecentAuditViewModel
{
    public IReadOnlyList<FwAuditLog> Entries { get; init; } = [];
    public string? ManageUrl { get; init; }
}

public sealed class PortForwardsSummaryViewModel
{
    public IReadOnlyList<PortForwardSummaryRow> Rows { get; init; } = [];
    public int TotalEnabled { get; init; }
    public int Total { get; init; }
    public string? ManageUrl { get; init; }
}

public sealed class PortForwardSummaryRow
{
    public required string External { get; init; }
    public required string Internal { get; init; }
    public string? Iface { get; init; }
    public string? Description { get; init; }
    public bool Enabled { get; init; }
}

public sealed class DropRulesViewModel
{
    public IReadOnlyList<DropRuleRow> Rows { get; init; } = [];
    public int TotalLive { get; init; }
    public string? ManageUrl { get; init; }
}

public sealed class DropRuleRow
{
    public required string Chain { get; init; }
    public required string Action { get; init; }
    public string? Description { get; init; }
    public required string Match { get; init; }
}

public sealed class ConntrackCardViewModel
{
    public required NetFirewall.Services.Monitoring.ConntrackMetrics Metrics { get; init; }
}
