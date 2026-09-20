using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Diagnostics;

namespace NetFirewall.Web.Models.Diagnostics;

// ─────────────────────────── page + form models ───────────────────────────

/// <summary>Select data every tool page needs: configured interfaces and traffic marks.</summary>
public sealed class DiagToolPageViewModel
{
    public IReadOnlyList<FwInterface> Interfaces { get; init; } = Array.Empty<FwInterface>();
    public IReadOnlyList<FwTrafficMark> Marks { get; init; } = Array.Empty<FwTrafficMark>();
    public string DefaultTarget { get; init; } = "1.1.1.1";
    public bool DaemonEnabled { get; init; } = true;

    public IReadOnlyList<FormFieldViewModel.SelectOption> InterfaceOptions(string anyLabel = "(default route)")
    {
        var list = new List<FormFieldViewModel.SelectOption> { new("", anyLabel) };
        list.AddRange(Interfaces.OrderBy(i => i.Type).ThenBy(i => i.Name)
            .Select(i => new FormFieldViewModel.SelectOption(i.Name, $"{i.Name} · {i.Type}")));
        return list;
    }

    public IReadOnlyList<FormFieldViewModel.SelectOption> MarkOptions()
    {
        var list = new List<FormFieldViewModel.SelectOption> { new("", "(no mark)") };
        list.AddRange(Marks.OrderBy(m => m.MarkValue)
            .Select(m => new FormFieldViewModel.SelectOption($"0x{m.MarkValue:x}", $"{m.Name} (0x{m.MarkValue:X})")));
        list.Add(new("custom", "Custom…"));
        return list;
    }
}

/// <summary>Shared "how to steer the probe" fields (interface + fwmark select with a custom escape hatch).</summary>
public sealed record SteeringFieldsViewModel(
    DiagToolPageViewModel Page,
    string? Interface,
    string? Fwmark,
    bool ShowInterface = true,
    string InterfaceLabel = "Out via interface",
    string InterfaceAnyLabel = "(default route)");

public abstract class SteeredFormViewModel
{
    [StringLength(15)]
    [RegularExpression(@"^[A-Za-z0-9_.\-]{0,15}$", ErrorMessage = "Invalid interface name.")]
    public string? Interface { get; set; }

    /// <summary>Select value: "", "0x…", or "custom" (then <see cref="FwmarkCustom"/> holds the value).</summary>
    [StringLength(12)]
    public string? Fwmark { get; set; }

    [StringLength(12)]
    [RegularExpression(@"^(0x[0-9A-Fa-f]{1,8}|[0-9]{1,10})?$", ErrorMessage = "Mark must be hex (0x500) or decimal.")]
    public string? FwmarkCustom { get; set; }

    public string? EffectiveFwmark =>
        string.Equals(Fwmark, "custom", StringComparison.OrdinalIgnoreCase)
            ? (string.IsNullOrWhiteSpace(FwmarkCustom) ? null : FwmarkCustom.Trim())
            : (string.IsNullOrWhiteSpace(Fwmark) ? null : Fwmark.Trim());
}

/// <summary>Loose client/Web shapes (HTML5 <c>pattern</c> + DataAnnotations); the daemon applies the strict allow-lists.</summary>
public static class DiagPatterns
{
    public const string Host = @"^[A-Za-z0-9.:\-]{1,253}$";
    public const string IpOrCidr = @"^[0-9A-Fa-f.:/]{0,49}$";
    public const string Iface = @"^[A-Za-z0-9_.\-]{0,15}$";
    public const string Fwmark = @"^(0x[0-9A-Fa-f]{1,8}|[0-9]{1,10})?$";
}

public sealed class PingFormViewModel : SteeredFormViewModel
{
    [Required, StringLength(253), RegularExpression(DiagPatterns.Host, ErrorMessage = "Enter an IP address or hostname.")]
    public string Target { get; set; } = string.Empty;

    [Range(1, 10)] public int Count { get; set; } = 3;
    [Range(1, 10)] public int TimeoutSec { get; set; } = 2;
}

public sealed class TracerouteFormViewModel : SteeredFormViewModel
{
    [Required, StringLength(253), RegularExpression(DiagPatterns.Host, ErrorMessage = "Enter an IP address or hostname.")]
    public string Target { get; set; } = string.Empty;

    [Range(1, 30)] public int MaxHops { get; set; } = 20;
    [Range(1, 5)]  public int TimeoutSec { get; set; } = 2;
}

public sealed class RouteGetFormViewModel : SteeredFormViewModel
{
    [Required, StringLength(253), RegularExpression(DiagPatterns.Host, ErrorMessage = "Enter an IP address or hostname.")]
    public string Target { get; set; } = string.Empty;

    [StringLength(45), RegularExpression(@"^[0-9A-Fa-f.:]{0,45}$", ErrorMessage = "From must be an IP address.")]
    public string? From { get; set; }
}

public sealed class ConntrackFormViewModel
{
    [StringLength(49), RegularExpression(@"^[0-9A-Fa-f.:/]{0,49}$", ErrorMessage = "IP or CIDR.")]
    public string? Src { get; set; }

    [StringLength(49), RegularExpression(@"^[0-9A-Fa-f.:/]{0,49}$", ErrorMessage = "IP or CIDR.")]
    public string? Dst { get; set; }

    [RegularExpression("^(tcp|udp|icmp)?$", ErrorMessage = "tcp, udp or icmp.")]
    public string? Proto { get; set; }

    [Range(1, 65535)] public int? Port { get; set; }
    [Range(1, 500)]   public int Limit { get; set; } = 200;
}

public sealed class DropLogFormViewModel
{
    [StringLength(15), RegularExpression(@"^[A-Za-z0-9_.\-]{0,15}$", ErrorMessage = "Invalid interface name.")]
    public string? Interface { get; set; }

    [Range(5, 1440)]  public int SinceMinutes { get; set; } = 60;
    [Range(50, 2000)] public int Lines { get; set; } = 500;

    [RegularExpression("^(drops|martians|wg|all)$")]
    public string Filter { get; set; } = "drops";
}

// ─────────────────────────── presentation records ───────────────────────────

public sealed record ToolCardViewModel(string Title, string Description, string Href, string IconPath, string? Badge = null, string BadgeClass = "badge-muted");

public sealed record ToolPageHeaderViewModel(string Title, string Subtitle, string? BackHref = "/Diagnostics");

public sealed record CopyButtonModel(string TargetSelector, string Label = "Copy");

public sealed record DiagRunMetaViewModel(Guid RunId, string Tool, string Status, DateTime StartedAtUtc, int DurationMs, string? Summary)
{
    public static DiagRunMetaViewModel From<T>(DiagRunEnvelope<T> env, string tool, string? summary = null) =>
        new(env.RunId, tool, env.Status, env.StartedAtUtc, env.DurationMs, summary);
}

/// <summary>A polled panel that must render even when the daemon is unreachable (no toast storms).</summary>
public sealed record PanelViewModel<T>(T? Data, string? Error);

public sealed class HistoryFilterViewModel
{
    [StringLength(40)] public string? Tool { get; set; }
    [StringLength(16)] public string? Status { get; set; }
    public DateTime? From { get; set; }
    public DateTime? To { get; set; }
    public bool Mine { get; set; }
    [Range(1, 100000)] public int Page { get; set; } = 1;
    /// <summary>Optional run to open in the drawer on load (deep link from a result's "Open in history").</summary>
    public Guid? Run { get; set; }
}

public sealed record RunsTableViewModel(IReadOnlyList<DiagRun> Rows, int Total, int Page, int PageSize, HistoryFilterViewModel Filter, string? Error = null)
{
    public int Pages => Math.Max(1, (int)Math.Ceiling(Total / (double)PageSize));
}

public sealed record RunDetailViewModel(DiagRun Run, string? Partial, object? Model, string PrettyParams, string? PrettyResult);

// ─────────────────────────── pure helpers ───────────────────────────

/// <summary>Status/tool → labels and badge classes. Pure, shared by every diagnostics view.</summary>
public static class DiagUi
{
    public static string BadgeClass(string? status) => status switch
    {
        DiagRunStatus.Ok      => "badge-success",
        DiagRunStatus.Warn    => "badge-warning",
        DiagRunStatus.Fail    => "badge-danger",
        DiagRunStatus.Running => "badge-info",
        DiagRunStatus.Busy    => "badge-info",
        _                     => "badge-muted", // error / timeout
    };

    public static string BadgeClass(DiagCheckStatus status) => status switch
    {
        DiagCheckStatus.Pass => "badge-success",
        DiagCheckStatus.Warn => "badge-warning",
        DiagCheckStatus.Fail => "badge-danger",
        _                    => "badge-muted",
    };

    public static string ToolLabel(string tool) => tool switch
    {
        DiagTools.Ping        => "Ping",
        DiagTools.Traceroute  => "Traceroute",
        DiagTools.RouteGet    => "Route oracle",
        DiagTools.Conntrack   => "Conntrack lookup",
        DiagTools.DropLog     => "Drop log",
        DiagTools.IfaceHealth => "Interface health",
        DiagTools.Sysctl      => "Kernel tunables",
        DiagTools.VpnDoctor   => "VPN doctor",
        DiagTools.VpnProbe    => "VPN data-plane probe",
        DiagTools.VpnCompare  => "VPN config compare",
        DiagTools.WanDoctor   => "WAN doctor",
        DiagTools.DhcpDoctor  => "DHCP doctor",
        DiagTools.DnsDoctor   => "DNS doctor",
        _                     => tool,
    };

    public static string ToolHref(string tool) => tool switch
    {
        DiagTools.Ping       => "/Diagnostics/ping",
        DiagTools.Traceroute => "/Diagnostics/traceroute",
        DiagTools.RouteGet   => "/Diagnostics/route",
        DiagTools.Conntrack  => "/Diagnostics/conntrack",
        DiagTools.DropLog    => "/Diagnostics/drop-log",
        DiagTools.Sysctl     => "/Diagnostics/sysctl",
        DiagTools.VpnDoctor or DiagTools.VpnProbe or DiagTools.VpnCompare => "/Diagnostics/Vpn",
        DiagTools.WanDoctor  => "/Diagnostics/Wan",
        DiagTools.DhcpDoctor => "/Diagnostics/Dhcp",
        DiagTools.DnsDoctor  => "/Diagnostics/Dns",
        _                    => "/Diagnostics",
    };

    public static string Ago(DateTime utc)
    {
        var span = DateTime.UtcNow - utc;
        return span.TotalSeconds < 60 ? "just now"
            : span.TotalMinutes < 60 ? $"{(int)span.TotalMinutes} min ago"
            : span.TotalHours < 48 ? $"{(int)span.TotalHours} h ago"
            : $"{(int)span.TotalDays} d ago";
    }

    public static string Bytes(long b) => b switch
    {
        >= 1L << 30 => $"{b / (double)(1L << 30):0.##} GB",
        >= 1L << 20 => $"{b / (double)(1L << 20):0.##} MB",
        >= 1L << 10 => $"{b / (double)(1L << 10):0.#} KB",
        _ => $"{b} B",
    };
}

/// <summary>
/// Maps a persisted <see cref="DiagRun"/> back to the result partial + model used
/// for live runs, so history renders exactly what the operator saw. Pure.
/// </summary>
public static class DiagRunPartials
{
    public static (string? Partial, object? Model) Resolve(DiagRun run)
    {
        if (string.IsNullOrEmpty(run.ResultJson) || run.ResultTruncated) return (null, null);
        return run.Tool switch
        {
            DiagTools.Ping       => ("~/Views/Diagnostics/_PingResult.cshtml",       Envelope<PingResult>(run)),
            DiagTools.Traceroute => ("~/Views/Diagnostics/_TracerouteResult.cshtml", Envelope<TracerouteResult>(run)),
            DiagTools.RouteGet   => ("~/Views/Diagnostics/_RouteResult.cshtml",      Envelope<RouteGetResult>(run)),
            DiagTools.Conntrack  => ("~/Views/Diagnostics/_ConntrackResult.cshtml",  Envelope<ConntrackLookupResult>(run)),
            DiagTools.DropLog    => ("~/Views/Diagnostics/_DropLogResult.cshtml",    Envelope<DropLogResult>(run)),
            DiagTools.VpnDoctor or DiagTools.WanDoctor or DiagTools.DhcpDoctor or DiagTools.DnsDoctor
                                 => ("~/Views/Shared/_DiagCheckList.cshtml",         Deserialize<DiagReport>(run.ResultJson)),
            _ => (null, null),
        };
    }

    private static DiagRunEnvelope<T>? Envelope<T>(DiagRun run)
    {
        var result = Deserialize<T>(run.ResultJson!);
        return result is null ? null : new DiagRunEnvelope<T>(run.Id, run.StartedAt, run.DurationMs ?? 0, run.Status, result);
    }

    private static T? Deserialize<T>(string json)
    {
        try { return JsonSerializer.Deserialize<T>(json, DiagnosticRunStore.JsonOpts); }
        catch (JsonException) { return default; }
    }

    public static string Pretty(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return string.Empty;
        try
        {
            using var doc = JsonDocument.Parse(json);
            return JsonSerializer.Serialize(doc.RootElement, new JsonSerializerOptions { WriteIndented = true });
        }
        catch (JsonException) { return json; }
    }
}

// ─────────────────────────── VPN doctor forms ───────────────────────────

public sealed class VpnProbeFormViewModel
{
    [StringLength(253), RegularExpression(DiagPatterns.Host, ErrorMessage = "Enter an IP address or hostname.")]
    public string? Target { get; set; }

    [RegularExpression("^(mark|bind|both)$")]
    public string Mode { get; set; } = "both";
}

public sealed class VpnCompareFormViewModel
{
    [Required(ErrorMessage = "Paste the config you were issued.")]
    [StringLength(16 * 1024, ErrorMessage = "Config is too large (16 KB max).")]
    public string ConfigText { get; set; } = string.Empty;
}

// ─────────────────────────── phase 2: invasive tools ───────────────────────────

public sealed class TraceFormViewModel
{
    [StringLength(49), RegularExpression(DiagPatterns.IpOrCidr, ErrorMessage = "IP or CIDR.")]
    public string? Src { get; set; }

    [StringLength(49), RegularExpression(DiagPatterns.IpOrCidr, ErrorMessage = "IP or CIDR.")]
    public string? Dst { get; set; }

    [RegularExpression("^(tcp|udp|icmp)?$", ErrorMessage = "tcp, udp or icmp.")]
    public string? Protocol { get; set; }

    [Range(1, 65535)] public int? Port { get; set; }

    [StringLength(15), RegularExpression(DiagPatterns.Iface, ErrorMessage = "Invalid interface name.")]
    public string? Interface { get; set; }

    [Range(5, 60)]    public int DurationSec { get; set; } = 20;
    [Range(10, 5000)] public int MaxEvents { get; set; } = 500;

    /// <summary>The daemon refuses an unfiltered trace; catch it here too so the operator gets an inline error.</summary>
    public bool HasMatcher =>
        !string.IsNullOrWhiteSpace(Src) || !string.IsNullOrWhiteSpace(Dst)
        || !string.IsNullOrWhiteSpace(Protocol) || !string.IsNullOrWhiteSpace(Interface);
}

public sealed class CaptureFormViewModel
{
    [Required, StringLength(15), RegularExpression(DiagPatterns.Iface, ErrorMessage = "Invalid interface name.")]
    public string Interface { get; set; } = string.Empty;

    /// <summary>pcap-filter syntax; the daemon re-validates and compiles it with `tcpdump -d`.</summary>
    [StringLength(200), RegularExpression(@"^[A-Za-z0-9 ._:/()\[\]<>=!&|,-]*$", ErrorMessage = "Only pcap-filter characters are allowed.")]
    public string? Filter { get; set; }

    [Range(5, 60)]      public int DurationSec { get; set; } = 20;
    [Range(10, 2000)]   public int MaxPackets { get; set; } = 500;
    [Range(64, 262144)] public int Snaplen { get; set; } = 262144;
}

/// <summary>Shell for a job page: the form plus whichever job is currently polling.</summary>
public sealed record JobPageViewModel(DiagToolPageViewModel Page, Guid? JobId = null, string? Error = null);

/// <summary>Everything the shared doctor page needs; the three doctors differ only in this copy.</summary>
public sealed record DoctorPageViewModel(string Title, string Subtitle, string RunUrl, string Blurb, bool DaemonEnabled)
{
    public static DoctorPageViewModel Wan(bool daemon) => new(
        "WAN doctor",
        "Your uplinks end to end: link and addressing, what the failover monitor is configured to probe and what it currently believes, whether each WAN's mark really routes out that WAN, who owns the default route, and a live probe per uplink.",
        "/Diagnostics/Wan/run",
        "A dual-WAN box fails in the gap between three sources of truth — the database, the kernel's policy routing, and the health monitor. This compares all three.",
        daemon);

    public static DoctorPageViewModel Dhcp(bool daemon) => new(
        "DHCP doctor",
        "The DHCP server unit and its listener, every enabled scope against the interface that is supposed to serve it, pool pressure, recent lease activity, and whether the firewall lets client requests in at all.",
        "/Diagnostics/Dhcp/run",
        "The DHCP server is installed opt-in, so \"not deployed\" is reported as skipped rather than broken.",
        daemon);

    public static DoctorPageViewModel Dns(bool daemon) => new(
        "DNS doctor",
        "The resolver unit and its listeners, a real query answered locally, the same query sent to each LAN address exactly as a client would, the firewall rules for port 53, and whether public resolvers are reachable at all.",
        "/Diagnostics/Dns/run",
        "Queries are sent as raw DNS over UDP, so no extra package is needed on the appliance.",
        daemon);
}
