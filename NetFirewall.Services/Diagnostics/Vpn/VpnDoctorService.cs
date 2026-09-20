using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Settings;
using NetFirewall.Services.Vpn;

namespace NetFirewall.Services.Diagnostics.Vpn;

public sealed class VpnDoctorService : IVpnDoctorService
{
    private const string Cat = "Config";

    private readonly IWireGuardService _wg;
    private readonly IEnumerable<IVpnDoctorCheck> _checks;
    private readonly IVpnDoctorContextFactory _contexts;
    private readonly Doctors.IDoctorRunner _runner;
    private readonly ISysctlSanityService _sysctl;
    private readonly IWgLiveReader _live;
    private readonly IPingProbeService _probes;
    private readonly IWireGuardImporter _importer;
    private readonly IDiagnosticInputValidator _validator;
    private readonly IAppSettingsService _settings;
    private readonly DiagnosticsOptions _opts;
    private readonly ILogger<VpnDoctorService> _logger;

    public VpnDoctorService(
        IWireGuardService wg,
        IEnumerable<IVpnDoctorCheck> checks,
        IVpnDoctorContextFactory contexts,
        Doctors.IDoctorRunner runner,
        ISysctlSanityService sysctl,
        IWgLiveReader live,
        IPingProbeService probes,
        IWireGuardImporter importer,
        IDiagnosticInputValidator validator,
        IAppSettingsService settings,
        IOptions<DiagnosticsOptions> opts,
        ILogger<VpnDoctorService> logger)
    {
        _wg = wg; _checks = checks; _contexts = contexts; _runner = runner; _sysctl = sysctl; _live = live;
        _probes = probes; _importer = importer; _validator = validator; _settings = settings;
        _opts = opts.Value; _logger = logger;
    }

    // ───────────────────────── doctor ─────────────────────────

    public async Task<DiagReport> RunAsync(VpnDoctorRequest request, CancellationToken ct = default)
    {
        var started = DateTime.UtcNow;
        var sw = Stopwatch.StartNew();

        var server = await _wg.GetServerAsync(ct);
        if (server is null)
        {
            return new DiagReport(DiagTools.VpnDoctor, "(no tunnel)", started, (int)sw.ElapsedMilliseconds,
            [
                DiagCheck.Fail("cfg.server", Cat, "WireGuard interface", "No WireGuard interface is configured — every other check is moot.",
                    new DiagRemedy("Create the tunnel", "/Vpn/WireGuard")),
            ]);
        }

        var peers = await _wg.GetPeersAsync(server.Id, ct);
        var ctx = _contexts.Create(server, peers, await ProbeTargetAsync(ct), ct);

        var report = await _runner.RunAsync(DiagTools.VpnDoctor, server.Name, ctx, _checks, ct);

        // The kernel tunables are shared with the Sysctl page, so they come from
        // that service rather than from a check of our own.
        var all = report.Checks.ToList();
        try
        {
            all.AddRange(await _sysctl.EvaluateAsync(server.Name, ct));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            all.Add(DiagCheck.Skip("sys.error", "Kernel", "Kernel tunables", $"Could not read sysctls: {ex.Message}"));
        }

        return new DiagReport(DiagTools.VpnDoctor, server.Name, started, (int)sw.ElapsedMilliseconds, all);
    }

    // ───────────────────────── data-plane probe ─────────────────────────

    public async Task<VpnProbeResult> ProbeAsync(VpnProbeRequest request, CancellationToken ct = default)
    {
        var server = await _wg.GetServerAsync(ct)
            ?? throw new InvalidOperationException("No WireGuard interface is configured.");
        var iface = server.Name;

        var before = await _live.DumpAsync(iface, ct);
        if (before is null)
            return new VpnProbeResult("no-interface", $"{iface} is not present — start the tunnel (Apply VPN) first.", 0, 0, 0, 0, null, null);

        var ctx = _contexts.Create(server, await _wg.GetPeersAsync(server.Id, ct), await ProbeTargetAsync(ct), ct);
        var mark = await ctx.TunnelMarkAsync();
        var host = string.IsNullOrWhiteSpace(request.Target) ? ctx.ProbeTarget : request.Target.Trim();
        var ip = await _probes.ResolveAsync(host, ct) ?? throw new InvalidOperationException($"Could not resolve '{host}'.");

        var mode = (request.Mode ?? "both").ToLowerInvariant();
        PingResult? byMark = null, byBind = null;
        if (mode is "mark" or "both")
            byMark = mark > 0
                ? await _probes.PingAsync(ip, null, mark, 3, 2, ct)
                : new PingResult(ip, ip, "no tunnel mark", 0, 0, 100, null, null, null, Array.Empty<PingReply>(), string.Empty, "No policy-routing mark is scaffolded for this tunnel.");
        if (mode is "bind" or "both")
            byBind = await _probes.PingAsync(ip, iface, 0, 3, 2, ct);

        var after = await _live.DumpAsync(iface, ct) ?? before;
        var (verdict, why) = Classify(byMark, byBind, before.TotalTx, after.TotalTx, before.TotalRx, after.TotalRx, mark, iface, ip);
        return new VpnProbeResult(verdict, why, before.TotalTx, after.TotalTx, before.TotalRx, after.TotalRx, byMark, byBind);
    }

    /// <summary>Pure classification — unit-tested on its own.</summary>
    internal static (string Verdict, string Explanation) Classify(
        PingResult? byMark, PingResult? byBind, long txBefore, long txAfter, long rxBefore, long rxAfter, long mark, string iface, string ip)
    {
        var replies = (byMark?.Received ?? 0) + (byBind?.Received ?? 0);
        var txGrew = txAfter > txBefore;
        var rxGrew = rxAfter > rxBefore;

        if (replies > 0)
            return ("ok", $"Replies from {ip} through {iface}: the tunnel carries traffic end to end.");

        if (byMark?.Error is not null && byBind is null)
            return ("inconclusive", byMark.Error);

        if (txGrew && !rxGrew)
            return ("remote-drops",
                $"Packets left through {iface} (tx +{txAfter - txBefore} B) but nothing came back. The far end is discarding them — " +
                "its AllowedIPs for this peer almost certainly do not include the address we send from. Compare with the issued config (Address line).");

        if (!txGrew && mark > 0)
            return ("local-routing",
                $"Nothing entered {iface}: the fwmark 0x{mark:x} lookup did not select the tunnel. Check the policy rule and that table '{iface}' still has its default route (Stop/Start empties it).");

        if (rxGrew && replies == 0)
            return ("replies-dropped",
                $"The far end answered ({iface} rx +{rxAfter - rxBefore} B) but the replies were dropped locally — strict rp_filter or an INPUT rule. See Kernel tunables.");

        return ("inconclusive", "No replies and no counter movement. If the handshake is fresh, retry; otherwise the tunnel is not established.");
    }

    // ───────────────────────── compare with issued config ─────────────────────────

    public async Task<VpnCompareResult> CompareIssuedConfigAsync(string redactedConfigText, CancellationToken ct = default)
    {
        // Redact again — never trust that the edge did it.
        var issued = _importer.Parse(_validator.RedactWgConfig(redactedConfigText ?? string.Empty));
        var server = await _wg.GetServerAsync(ct)
            ?? throw new InvalidOperationException("No WireGuard interface is configured.");
        var peers = await _wg.GetPeersAsync(server.Id, ct);
        return Compare(issued, server, peers);
    }

    /// <summary>Pure diff — unit-tested on its own.</summary>
    internal static VpnCompareResult Compare(WgQuickConfig issued, WgServer server, IReadOnlyList<WgPeer> peers)
    {
        var diffs = new List<VpnCompareDifference>();
        var upstream = peers.FirstOrDefault(p => p.Enabled && VpnDoctorContext.IsRole(p, "upstream"))
                       ?? peers.FirstOrDefault(p => p.Enabled && VpnDoctorContext.IsRole(p, "site"));
        var issuedPeer = issued.Peers.FirstOrDefault();

        // Address: the single most consequential line — the far end only accepts this source.
        if (issued.Address is null)
            diffs.Add(new("Address", null, server.AddressCidr, DiagCheckStatus.Skip, "The pasted config has no Address line."));
        else if (!SameCidr(issued.Address, server.AddressCidr))
            diffs.Add(new("Address", issued.Address, server.AddressCidr, DiagCheckStatus.Fail,
                $"They issued {issued.Address}; this firewall runs {server.AddressCidr}. The server silently drops data from any other source — set the interface address to {issued.Address} and Apply VPN."));
        else
            diffs.Add(new("Address", issued.Address, server.AddressCidr, DiagCheckStatus.Pass, "Match."));

        // Their [Peer] PublicKey is THEIR server key — it must equal what we dial.
        if (issuedPeer?.PublicKey is { } theirKey)
        {
            if (upstream is null)
                diffs.Add(new("Peer public key", theirKey, null, DiagCheckStatus.Warn, "No upstream/site peer configured here to compare against."));
            else if (!string.Equals(theirKey, upstream.PublicKey, StringComparison.Ordinal))
                diffs.Add(new("Peer public key", theirKey, upstream.PublicKey, DiagCheckStatus.Fail, $"The key we dial for '{upstream.Name}' is not the server key in the issued config — the handshake cannot complete."));
            else
                diffs.Add(new("Peer public key", theirKey, upstream.PublicKey, DiagCheckStatus.Pass, "Match."));
        }

        if (issuedPeer?.Endpoint is { } ep && upstream is not null)
            diffs.Add(string.Equals(ep, upstream.Endpoint, StringComparison.OrdinalIgnoreCase)
                ? new("Endpoint", ep, upstream.Endpoint, DiagCheckStatus.Pass, "Match.")
                : new("Endpoint", ep, upstream.Endpoint, DiagCheckStatus.Warn, "Different endpoint — fine if the server has several addresses, otherwise fix the peer."));

        if (issuedPeer is not null && upstream is not null)
        {
            var theirs = string.Join(", ", issuedPeer.AllowedIps.OrderBy(a => a, StringComparer.Ordinal));
            var ours = string.Join(", ", upstream.AllowedIps.OrderBy(a => a, StringComparer.Ordinal));
            diffs.Add(string.Equals(theirs, ours, StringComparison.Ordinal)
                ? new("AllowedIPs", theirs, ours, DiagCheckStatus.Pass, "Match.")
                : new("AllowedIPs", theirs, ours, DiagCheckStatus.Warn, "Different AllowedIPs. With Table=off this only affects which sources WireGuard accepts from the peer (cryptokey routing)."));
        }

        if (issued.Mtu is { } mtu && server.Mtu is { } ourMtu && mtu != ourMtu)
            diffs.Add(new("MTU", mtu.ToString(), ourMtu.ToString(), DiagCheckStatus.Warn, "MTU differs from the issued value."));

        if (issued.Dns is not null)
            diffs.Add(new("DNS", issued.Dns, null, DiagCheckStatus.Pass, "Informational — the firewall does not push tunnel DNS to itself."));

        var overall = diffs.Any(d => d.Severity == DiagCheckStatus.Fail) ? DiagCheckStatus.Fail
            : diffs.Any(d => d.Severity == DiagCheckStatus.Warn) ? DiagCheckStatus.Warn
            : DiagCheckStatus.Pass;
        return new VpnCompareResult(diffs, overall);
    }

    private static bool SameCidr(string a, string b)
    {
        static (string Ip, int Prefix) Split(string s)
        {
            var i = s.IndexOf('/');
            return i < 0 ? (s.Trim(), -1) : (s[..i].Trim(), int.TryParse(s[(i + 1)..], out var p) ? p : -1);
        }
        var (ia, pa) = Split(a);
        var (ib, pb) = Split(b);
        // /32 and no prefix mean the same host; anything else must match exactly.
        return string.Equals(ia, ib, StringComparison.OrdinalIgnoreCase) && (pa == pb || (pa is -1 or 32 && pb is -1 or 32));
    }

    private async Task<string> ProbeTargetAsync(CancellationToken ct)
    {
        try
        {
            var t = await _settings.GetStringAsync("diagnostics.probe_default_target", ct);
            return string.IsNullOrWhiteSpace(t) ? "1.1.1.1" : t.Trim();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogDebug(ex, "probe default target unavailable");
            return "1.1.1.1";
        }
    }
}
