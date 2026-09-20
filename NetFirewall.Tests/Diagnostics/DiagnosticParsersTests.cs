using NetFirewall.Models.Vpn;
using NetFirewall.Services.Diagnostics;

namespace NetFirewall.Tests.Diagnostics;

/// <summary>Pure parsers over captured tool output. No processes, no Linux required.</summary>
public class DiagnosticParsersTests
{
    // ───────────────────────── ping ─────────────────────────

    private const string PingOk = """
        PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
        64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=40.1 ms
        64 bytes from 1.1.1.1: icmp_seq=2 ttl=57 time=41.0 ms
        64 bytes from 1.1.1.1: icmp_seq=3 ttl=57 time=42.2 ms

        --- 1.1.1.1 ping statistics ---
        3 packets transmitted, 3 received, 0% packet loss, time 2003ms
        rtt min/avg/max/mdev = 40.100/41.100/42.200/0.858 ms
        """;

    [Fact]
    public void Ping_ParsesRepliesSummaryAndRtt()
    {
        var r = PingProbeService.ParsePing("1.1.1.1", "fwmark 0x500", PingOk, "", 0);

        Assert.Equal(3, r.Sent);
        Assert.Equal(3, r.Received);
        Assert.Equal(0, r.LossPct);
        Assert.Equal(3, r.Replies.Count);
        Assert.Equal(57, r.Replies[0].Ttl);
        Assert.Equal(42.2, r.Replies[2].TimeMs);
        Assert.Equal(41.1, r.RttAvgMs);
        Assert.Equal("fwmark 0x500", r.Via);
        Assert.Null(r.Error);
    }

    [Fact]
    public void Ping_AllLost_HasNoRttAndNoError()
    {
        const string lost = """
            PING 192.168.3.1 (192.168.3.1) 56(84) bytes of data.

            --- 192.168.3.1 ping statistics ---
            3 packets transmitted, 0 received, 100% packet loss, time 2047ms
            """;
        var r = PingProbeService.ParsePing("192.168.3.1", "iface wg0", lost, "", 1);

        Assert.Equal(3, r.Sent);
        Assert.Equal(0, r.Received);
        Assert.Equal(100, r.LossPct);
        Assert.Null(r.RttAvgMs);
        Assert.Null(r.Error);   // exit 1 = no replies, the tool itself worked
    }

    [Fact]
    public void Ping_ExitTwo_IsAnError_WithStderr()
    {
        var r = PingProbeService.ParsePing("1.1.1.1", "fwmark 0x500", "", "ping: socket: Operation not permitted\n", 2);
        Assert.Equal("ping: socket: Operation not permitted", r.Error);
        Assert.Equal(0, r.Sent);
    }

    [Fact]
    public void Ping_CountsErrorsLine()
    {
        const string withErrors = """
            PING 10.9.9.9 (10.9.9.9) 56(84) bytes of data.
            From 192.168.99.1 icmp_seq=1 Destination Host Unreachable

            --- 10.9.9.9 ping statistics ---
            3 packets transmitted, 0 received, +1 errors, 100% packet loss, time 2050ms
            """;
        var r = PingProbeService.ParsePing("10.9.9.9", "default route", withErrors, "", 1);
        Assert.Equal(3, r.Sent);
        Assert.Equal(0, r.Received);
        Assert.Equal(100, r.LossPct);
    }

    // ───────────────────────── traceroute ─────────────────────────

    [Fact]
    public void Traceroute_ParsesHopsAndStars()
    {
        const string tr = """
            traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 60 byte packets
             1  154.12.104.129  0.612 ms
             2  *
             3  172.16.0.1  8.201 ms
             4  1.1.1.1  12.004 ms
            """;
        var r = PingProbeService.ParseTraceroute("1.1.1.1", "iface ens192", tr);

        Assert.Equal(4, r.Hops.Count);
        Assert.Equal("154.12.104.129", r.Hops[0].Ip);
        Assert.Null(r.Hops[1].Ip);
        Assert.Equal(12.004, r.Hops[3].RttMs.Single());
        Assert.True(r.Reached);
    }

    // ───────────────────────── ip route get / rule / route ─────────────────────────

    [Fact]
    public void RouteGet_Json_PicksDevGatewaySrcTableMark()
    {
        const string json = """[{"dst":"1.1.1.1","gateway":"154.12.104.129","dev":"ens192","table":"wan1","prefsrc":"154.12.104.135","flags":[],"uid":0,"mark":256,"cache":[]}]""";
        var r = RouteOracleService.ParseRouteGet("1.1.1.1", 256, json);

        Assert.Equal("ens192", r.Dev);
        Assert.Equal("154.12.104.129", r.Gateway);
        Assert.Equal("154.12.104.135", r.Src);
        Assert.Equal("wan1", r.Table);
        Assert.Equal("0x100", r.Mark);
        Assert.Empty(r.Warnings);
    }

    [Fact]
    public void RouteGet_MarkedLookupWithoutTable_WarnsAboutFallThrough()
    {
        // The Stop/Start symptom: table wg0 is empty, the 0x500 lookup lands in main.
        const string json = """[{"dst":"1.1.1.1","gateway":"154.12.104.129","dev":"ens192","prefsrc":"154.12.104.135","flags":[],"uid":0,"mark":1280,"cache":[]}]""";
        var r = RouteOracleService.ParseRouteGet("1.1.1.1", 1280, json);

        Assert.Equal("ens192", r.Dev);
        Assert.Null(r.Table);
        Assert.Contains(r.Warnings, w => w.Contains("fell through", StringComparison.Ordinal));
    }

    [Fact]
    public void RouteGet_TextFallback_StillFindsDevAndVia()
    {
        const string text = "1.1.1.1 via 154.12.104.129 dev ens192 table wan1 src 154.12.104.135 uid 0 \n    cache \n";
        var r = RouteOracleService.ParseRouteGet("1.1.1.1", 0, text);
        Assert.Equal("ens192", r.Dev);
        Assert.Equal("154.12.104.129", r.Gateway);
        Assert.Equal("wan1", r.Table);
    }

    [Fact]
    public void IpRules_ParseFwmarkHexAndMasked()
    {
        const string json = """[{"priority":0,"src":"all","table":"local"},{"priority":100,"src":"all","fwmark":"0x100","table":"wan1"},{"priority":120,"src":"all","fwmark":"0x500/0xffff","table":"wg0"},{"priority":32766,"src":"all","table":"main"}]""";
        var rules = RouteOracleService.ParseRules(json);

        Assert.Equal(4, rules.Count);
        Assert.Equal(256, rules[1].Fwmark);
        Assert.Equal(1280, rules[2].Fwmark);
        Assert.Equal("wg0", rules[2].Table);
        Assert.Null(rules[0].Fwmark);
    }

    [Fact]
    public void IpRoutes_ParseDefaultDevRoute()
    {
        const string json = """[{"dst":"default","dev":"wg0","scope":"link","metric":100,"flags":[]}]""";
        var routes = RouteOracleService.ParseRoutes(json);
        var r = Assert.Single(routes);
        Assert.Equal("default", r.Destination);
        Assert.Equal("wg0", r.Dev);
        Assert.Equal(100, r.Metric);
    }

    // ───────────────────────── conntrack ─────────────────────────

    [Fact]
    public void Conntrack_ParsesOriginalAndReplyTuples_RevealingNat()
    {
        const string line = "ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.99.60 dst=1.1.1.1 sport=51234 dport=443 packets=10 bytes=1200 src=1.1.1.1 dst=192.168.3.2 sport=443 dport=51234 packets=8 bytes=900 [ASSURED] mark=1280 use=1";
        var f = ConntrackLookupService.ParseLine(line);

        Assert.NotNull(f);
        Assert.Equal("tcp", f.Proto);
        Assert.Equal("192.168.99.60", f.Src);
        Assert.Equal("1.1.1.1", f.Dst);
        Assert.Equal(443, f.Dport);
        Assert.Equal("ESTABLISHED", f.State);
        Assert.Equal("0x500", f.Mark);
        Assert.Equal(1200, f.BytesOrig);
        Assert.Equal(900, f.BytesReply);
        Assert.Equal("192.168.3.2", f.ReplyDst);   // masqueraded to the tunnel address → it went via wg0
    }

    [Fact]
    public void Conntrack_UdpUnreplied_AndLimit()
    {
        const string udp = "ipv4     2 udp      17 29 src=192.168.99.104 dst=8.8.8.8 sport=5353 dport=53 packets=1 bytes=64 [UNREPLIED] src=8.8.8.8 dst=154.12.104.135 sport=53 dport=5353 packets=0 bytes=0 mark=0 use=1";
        var one = ConntrackLookupService.ParseLine(udp)!;
        Assert.Equal("udp", one.Proto);
        Assert.Equal("UNREPLIED", one.State);
        Assert.Null(one.Mark);

        var many = string.Join('\n', Enumerable.Repeat(udp, 5));
        var r = ConntrackLookupService.Parse(many, limit: 2);
        Assert.Equal(5, r.Total);
        Assert.Equal(2, r.Flows.Count);
        Assert.True(r.Truncated);
    }

    [Fact]
    public void Conntrack_IgnoresNoise()
    {
        Assert.Null(ConntrackLookupService.ParseLine("conntrack v1.4.7 (conntrack-tools): 3 flow entries have been shown."));
    }

    // ───────────────────────── drop log ─────────────────────────

    private const string Journal = """
        2026-09-18T21:11:51-0600 myFirewall kernel: 5:185m5:185mINPUT_DROP: IN=ens192 OUT= MAC=44:2b:03:7e:9e:a4 SRC=94.154.43.131 DST=154.12.104.135 LEN=60 TOS=0x00 PREC=0x00 TTL=248 ID=20003 DF PROTO=TCP SPT=48597 DPT=17706 WINDOW=64240 RES=0x00 SYN URGP=0 MARK=0x500
        2026-09-18T21:11:52-0600 myFirewall kernel: FORWARD_DROP: IN=wg0 OUT=ens256 SRC=192.168.1.53 DST=192.168.99.10 PROTO=UDP SPT=5060 DPT=5060 LEN=20
        2026-09-18T21:11:53-0600 myFirewall kernel: IPv4: martian source 154.12.104.135 from 1.1.1.1, on dev wg0
        2026-09-18T21:11:54-0600 myFirewall kernel: wireguard: wg0: Handshake for peer 3 (73.213.125.58:51820) did not complete after 5 seconds, retrying
        2026-09-18T21:11:55-0600 myFirewall kernel: usb 1-1: new high-speed USB device
        """;

    [Fact]
    public void DropLog_ParsesNflogLines_StripsArtifacts_AndBuildsTops()
    {
        var r = DropLogService.Parse(Journal, iface: null, filter: "drops", requestedLines: 500);

        Assert.Equal(5, r.Scanned);
        Assert.Equal(2, r.Entries.Count);
        var e = r.Entries[0];
        Assert.Equal("INPUT_DROP", e.Prefix);
        Assert.Equal("ens192", e.In);
        Assert.Null(e.Out);
        Assert.Equal("94.154.43.131", e.Src);
        Assert.Equal("TCP", e.Proto);
        Assert.Equal(17706, e.Dpt);
        Assert.Equal("0x500", e.Mark);
        Assert.NotNull(e.At);
        Assert.Equal("tcp/17706", r.TopPorts[0].Key);
        Assert.False(r.Truncated);
    }

    [Fact]
    public void DropLog_InterfaceFilter_MatchesInOrOut()
    {
        var r = DropLogService.Parse(Journal, iface: "wg0", filter: "drops", requestedLines: 500);
        var e = Assert.Single(r.Entries);
        Assert.Equal("FORWARD_DROP", e.Prefix);
        Assert.Equal("wg0", e.In);
        Assert.Equal("ens256", e.Out);
    }

    [Fact]
    public void DropLog_MartianAndWgFilters()
    {
        var martians = DropLogService.Parse(Journal, null, "martians", 500);
        var m = Assert.Single(martians.Entries);
        Assert.Equal("1.1.1.1", m.Src);
        Assert.Equal("wg0", m.In);

        var wg = DropLogService.Parse(Journal, null, "wg", 500);
        Assert.Single(wg.Entries);
        Assert.Contains("Handshake", wg.Entries[0].Raw);

        var all = DropLogService.Parse(Journal, null, "all", 500);
        Assert.Equal(5, all.Entries.Count);
    }

    // ───────────────────────── wg show dump ─────────────────────────

    [Fact]
    public void WgDump_DropsSecrets_ParsesInterfaceAndPeers()
    {
        var dump = "PRIVATEKEYSECRET=\tDDVeti4ALo+sS7MHYXjy9R1tU0Bw45Y53fg3ZdjlNw0=\t0\toff\n" +
                   "KBcsMr88nIPsoKJD4dSw1fvNtjDUdhchkhHKJU4LgH4=\tPSKSECRET=\t73.213.125.58:51820\t0.0.0.0/0\t1758252709\t76075000\t14010000\t25\n" +
                   "LAPTOPKEY=\t(none)\t(none)\t10.10.0.5/32\t0\t0\t0\toff\n";

        var d = WgDumpParser.Parse(dump);

        Assert.Equal("DDVeti4ALo+sS7MHYXjy9R1tU0Bw45Y53fg3ZdjlNw0=", d.PublicKey);
        Assert.Null(d.ListenPort);
        Assert.Equal("off", d.Fwmark);
        Assert.Equal(2, d.Peers.Count);

        var up = d.Peers[0];
        Assert.Equal("73.213.125.58:51820", up.Endpoint);
        Assert.Equal(["0.0.0.0/0"], up.AllowedIps);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1758252709).UtcDateTime, up.LatestHandshakeUtc);
        Assert.Equal(25, up.PersistentKeepalive);
        Assert.Equal(76075000, d.TotalRx);

        var laptop = d.Peers[1];
        Assert.Null(laptop.Endpoint);
        Assert.Null(laptop.LatestHandshakeUtc);
        Assert.Null(laptop.PersistentKeepalive);

        var json = System.Text.Json.JsonSerializer.Serialize(d);
        Assert.DoesNotContain("PRIVATEKEYSECRET", json);
        Assert.DoesNotContain("PSKSECRET", json);
    }

    // ───────────────────────── iproute2 addr / neigh ─────────────────────────

    [Fact]
    public void Addresses_AndNeighbors_ParseIprouteJson()
    {
        const string addr = """[{"ifindex":2,"ifname":"ens192","addr_info":[{"family":"inet","local":"154.12.104.135","prefixlen":29},{"family":"inet6","local":"fe80::1","prefixlen":64}]},{"ifindex":7,"ifname":"wg0","addr_info":[{"family":"inet","local":"192.168.3.2","prefixlen":32}]}]""";
        var map = InterfaceHealthService.ParseAddresses(addr);
        Assert.Equal(["154.12.104.135/29", "fe80::1/64"], map["ens192"]);
        Assert.Equal(["192.168.3.2/32"], map["wg0"]);

        const string neigh = """[{"dst":"192.168.99.1","dev":"ens256","lladdr":"0c:79:55:a3:af:1b","state":["REACHABLE"]},{"dst":"192.168.99.77","dev":"ens256","state":["FAILED"]}]""";
        var n = InterfaceHealthService.ParseNeighbors(neigh);
        Assert.Equal(2, n.Count);
        Assert.Equal("0c:79:55:a3:af:1b", n[0].Mac);
        Assert.Null(n[1].Mac);
        Assert.Equal("FAILED", n[1].State);
    }
}
