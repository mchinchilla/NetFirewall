namespace NetFirewall.Models.Vpn;

/// <summary>
/// Parsed <c>wg show &lt;iface&gt; dump</c>. Secrets are dropped at parse time: the
/// interface private key (column 1 of line 1) and each peer's preshared key
/// (column 2 of peer lines) never make it into this shape, so it is safe to
/// persist as diagnostics evidence.
/// </summary>
public sealed record WgDump(
    string? PublicKey,
    int? ListenPort,
    /// <summary><c>off</c> or <c>0x…</c> exactly as wg prints it.</summary>
    string Fwmark,
    IReadOnlyList<WgDumpPeer> Peers)
{
    public long TotalRx => Peers.Sum(p => p.RxBytes);
    public long TotalTx => Peers.Sum(p => p.TxBytes);
}

public sealed record WgDumpPeer(
    string PublicKey,
    string? Endpoint,
    IReadOnlyList<string> AllowedIps,
    DateTime? LatestHandshakeUtc,
    long RxBytes,
    long TxBytes,
    int? PersistentKeepalive);

/// <summary>Pure parser for the tab-separated dump format (shared by the apply service and the diagnostics reader).</summary>
public static class WgDumpParser
{
    public static WgDump Parse(string output)
    {
        var lines = (output ?? string.Empty).Split('\n', StringSplitOptions.RemoveEmptyEntries);
        if (lines.Length == 0) return new WgDump(null, null, "off", Array.Empty<WgDumpPeer>());

        // line 1: private_key \t public_key \t listen_port \t fwmark
        var head = lines[0].Split('\t');
        var pub  = head.Length > 1 && head[1] != "(none)" ? head[1] : null;
        int? port = head.Length > 2 && int.TryParse(head[2], out var p) && p > 0 ? p : null;
        var fwmark = head.Length > 3 && !string.IsNullOrWhiteSpace(head[3]) ? head[3].Trim() : "off";

        var peers = new List<WgDumpPeer>();
        foreach (var line in lines.Skip(1))
        {
            // pub \t psk \t endpoint \t allowed_ips \t latest_handshake \t rx \t tx \t keepalive
            var f = line.Split('\t');
            if (f.Length < 8) continue;

            var endpoint = f[2] == "(none)" ? null : f[2];
            var allowed = f[3] == "(none)"
                ? Array.Empty<string>()
                : f[3].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            DateTime? hs = long.TryParse(f[4], out var ts) && ts > 0
                ? DateTimeOffset.FromUnixTimeSeconds(ts).UtcDateTime
                : null;
            long.TryParse(f[5], out var rx);
            long.TryParse(f[6], out var tx);
            int? keepalive = int.TryParse(f[7], out var ka) && ka > 0 ? ka : null;

            peers.Add(new WgDumpPeer(f[0], endpoint, allowed, hs, rx, tx, keepalive));
        }
        return new WgDump(pub, port, fwmark, peers);
    }
}
