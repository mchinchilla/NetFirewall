using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Monitoring;

namespace NetFirewall.Services.Diagnostics;

public sealed class SysctlSanityService : ISysctlSanityService
{
    private const string Cat = "Kernel";

    private readonly ISysctlReader _sysctl;
    private readonly ISystemMonitorService _monitor;

    public SysctlSanityService(ISysctlReader sysctl, ISystemMonitorService monitor)
    {
        _sysctl = sysctl;
        _monitor = monitor;
    }

    public async Task<IReadOnlyList<DiagCheck>> EvaluateAsync(string? iface, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsLinux())
            return [DiagCheck.Skip("sys.platform", Cat, "Kernel tunables", "Linux only — nothing to inspect on this host.")];

        var checks = new List<DiagCheck>
        {
            await IpForwardAsync(ct),
            await RpFilterAsync(iface, ct),
            await LogMartiansAsync(ct),
            await ConntrackAsync(ct),
        };
        return checks;
    }

    private async Task<DiagCheck> IpForwardAsync(CancellationToken ct)
    {
        const string key = "net/ipv4/ip_forward";
        var v = await _sysctl.ReadAsync(key, ct);
        var ev = Evidence(key, v);
        return v switch
        {
            "1"  => DiagCheck.Pass("sys.ip_forward", Cat, "IPv4 forwarding", "ip_forward = 1", evidence: ev),
            null => DiagCheck.Skip("sys.ip_forward", Cat, "IPv4 forwarding", "Could not read ip_forward."),
            _    => DiagCheck.Fail("sys.ip_forward", Cat, "IPv4 forwarding", $"ip_forward = {v} — the box will not route between interfaces.",
                        new DiagRemedy("Enable forwarding", null, "sysctl -w net.ipv4.ip_forward=1 (the deploy/sysctl drop-in sets it permanently)"), evidence: ev),
        };
    }

    private async Task<DiagCheck> RpFilterAsync(string? iface, CancellationToken ct)
    {
        const string allKey = "net/ipv4/conf/all/rp_filter";
        var all = await _sysctl.ReadAsync(allKey, ct);
        var evidence = new List<DiagEvidence> { Evidence(allKey, all)[0] };
        int? effective = ParseInt(all);
        string? ifaceVal = null;

        if (!string.IsNullOrEmpty(iface))
        {
            var ifKey = $"net/ipv4/conf/{iface}/rp_filter";
            ifaceVal = await _sysctl.ReadAsync(ifKey, ct);
            evidence.Add(Evidence(ifKey, ifaceVal)[0]);
            // Kernel semantics: the stricter of `all` and the per-device value applies.
            if (ParseInt(ifaceVal) is { } iv) effective = Math.Max(effective ?? 0, iv);
        }

        if (effective is null)
            return DiagCheck.Skip("sys.rp_filter", Cat, "Reverse-path filter", "Could not read rp_filter.");

        var scope = iface is null ? "all" : $"all/{iface}";
        return effective switch
        {
            1 => DiagCheck.Fail("sys.rp_filter", Cat, "Reverse-path filter",
                    $"rp_filter effective = 1 (strict) on {scope} — replies arriving on a policy-routed link (VPN, secondary WAN) are dropped before nftables sees them.",
                    new DiagRemedy("Set loose mode", null, "deploy/sysctl ships rp_filter=2 (loose); check for a drop-in overriding it: sysctl -a | grep rp_filter"),
                    evidence: evidence),
            2 => DiagCheck.Pass("sys.rp_filter", Cat, "Reverse-path filter", $"rp_filter = 2 (loose) on {scope}.", evidence: evidence),
            _ => DiagCheck.Pass("sys.rp_filter", Cat, "Reverse-path filter", $"rp_filter = 0 (off) on {scope} — nftables anti-spoof rules do the job.", evidence: evidence),
        };
    }

    private async Task<DiagCheck> LogMartiansAsync(CancellationToken ct)
    {
        const string key = "net/ipv4/conf/all/log_martians";
        var v = await _sysctl.ReadAsync(key, ct);
        var ev = Evidence(key, v);
        return v switch
        {
            "1"  => DiagCheck.Pass("sys.log_martians", Cat, "Martian logging", "log_martians = 1 — rp_filter drops show up in the kernel log.", evidence: ev),
            null => DiagCheck.Skip("sys.log_martians", Cat, "Martian logging", "Could not read log_martians."),
            _    => DiagCheck.Warn("sys.log_martians", Cat, "Martian logging", "log_martians = 0 — reverse-path drops are silent, which makes routing problems invisible.",
                        new DiagRemedy("Enable", null, "sysctl -w net.ipv4.conf.all.log_martians=1"), evidence: ev),
        };
    }

    private async Task<DiagCheck> ConntrackAsync(CancellationToken ct)
    {
        var m = await _monitor.GetConntrackMetricsAsync(ct);
        if (!m.Available)
            return DiagCheck.Skip("sys.conntrack", Cat, "Connection tracking", "nf_conntrack counters not readable (module not loaded?).");

        var summary = $"{m.Count:N0} / {m.Max:N0} entries ({m.UsagePercent:0.#} %)";
        var ev = new[] { new DiagEvidence("/proc/sys/net/netfilter/nf_conntrack_{count,max}", $"{m.Count} / {m.Max}") };
        return m.UsagePercent switch
        {
            >= 95 => DiagCheck.Fail("sys.conntrack", Cat, "Connection tracking", $"Table nearly full: {summary}. New connections will be dropped.",
                        new DiagRemedy("Raise nf_conntrack_max", "/Monitoring", "sysctl -w net.netfilter.nf_conntrack_max=<higher>; look for a flow flood in Monitoring → Top talkers"), evidence: ev),
            >= 80 => DiagCheck.Warn("sys.conntrack", Cat, "Connection tracking", $"Table filling up: {summary}.",
                        new DiagRemedy("Review", "/Monitoring"), evidence: ev),
            _     => DiagCheck.Pass("sys.conntrack", Cat, "Connection tracking", summary, evidence: ev),
        };
    }

    private static IReadOnlyList<DiagEvidence> Evidence(string key, string? value) =>
        [new DiagEvidence($"cat /proc/sys/{key}", value ?? "(unreadable)")];

    private static int? ParseInt(string? s) => int.TryParse(s, out var v) ? v : null;
}
