using System.Net;
using System.Runtime.Versioning;
using NetFirewall.Services.Monitoring;
using Xunit;

namespace NetFirewall.Tests.Monitoring;

// ConntrackSamplerService is [SupportedOSPlatform("linux")]; the methods under
// test are pure (no real platform dependency), so we just mark the test class to
// silence CA1416 — the logic runs fine cross-platform.
[SupportedOSPlatform("linux")]

/// <summary>
/// Pure-function coverage for the conntrack sampler's flow classification — the
/// Phase 0 attribution fix. Fixtures use REAL conntrack lines captured from the
/// production firewall (tekium) during the Echo Show investigation, so the tests
/// pin the exact behaviour that was wrong before:
///   - service port came from Math.Min(sport,dport) → mislabelled DNS/media,
///   - the SNAT reply tuple's dst (= our WAN IP) could be recorded as the dest.
/// </summary>
public sealed class ConntrackSamplerClassificationTests
{
    // tekium's LAN and own IPs (from `ip -4 addr show`).
    private static readonly IPNetwork Lan = IPNetwork.Parse("192.168.99.0/24");
    private static readonly IReadOnlySet<IPAddress> OwnIps = new HashSet<IPAddress>
    {
        IPAddress.Parse("154.12.104.135"),   // WAN
        IPAddress.Parse("190.107.150.161"),  // WAN
        IPAddress.Parse("192.168.3.2"),      // WAN/transit
        IPAddress.Parse("192.168.99.1"),     // LAN gateway
        IPAddress.Loopback,
    };

    private static ConntrackSamplerService.Flow Parse(string line)
    {
        Assert.True(ConntrackSamplerService.TryParseFlow(line, out var flow), $"failed to parse: {line}");
        return flow;
    }

    // ── TryParseFlow ──────────────────────────────────────────────────────

    [Fact]
    public void TryParseFlow_reads_forward_tuple_and_both_byte_counters()
    {
        // Real line: Echo Show → AWS over HTTPS. Forward tuple printed first.
        const string line = "ipv4 2 tcp 6 431992 ESTABLISHED " +
            "src=192.168.99.126 dst=3.217.147.217 sport=53792 dport=443 packets=1814 bytes=561470 " +
            "src=3.217.147.217 dst=154.12.104.135 sport=443 dport=53792 packets=2184 bytes=1047157 [ASSURED] mark=0 use=1";

        var flow = Parse(line);

        Assert.Equal(IPAddress.Parse("192.168.99.126"), flow.Key.Src);
        Assert.Equal(IPAddress.Parse("3.217.147.217"), flow.Key.Dst);   // forward dst, NOT the reply's 154.x
        Assert.Equal(443, flow.Key.DstPort);
        Assert.Equal("tcp", flow.Key.Proto);
        Assert.Equal(561470, flow.OutgoingBytes);  // upload = forward tuple bytes
        Assert.Equal(1047157, flow.IncomingBytes); // download = reply tuple bytes
    }

    [Theory]
    [InlineData("ipv6 10 tcp 6 src=fe80::1 dst=fe80::2 sport=1 dport=2 bytes=10", false)] // ipv6 skipped
    [InlineData("garbage line with no proto token", false)]
    public void TryParseFlow_rejects_unparseable(string line, bool expected)
        => Assert.Equal(expected, ConntrackSamplerService.TryParseFlow(line, out _));

    // ── ClassifyFlow ──────────────────────────────────────────────────────

    [Fact]
    public void ClassifyFlow_records_real_destination_not_wan_ip()
    {
        // The reply tuple carries dst=154.12.104.135 (our WAN). Must record the
        // forward dst (3.217.147.217), never our own IP.
        var flow = Parse("ipv4 2 tcp 6 431992 ESTABLISHED " +
            "src=192.168.99.126 dst=3.217.147.217 sport=53792 dport=443 packets=1 bytes=561470 " +
            "src=3.217.147.217 dst=154.12.104.135 sport=443 dport=53792 packets=1 bytes=1047157 mark=0 use=1");

        var kept = ConntrackSamplerService.ClassifyFlow(flow, Lan, OwnIps,
            out var lanSrc, out var dstIp, out var port, out var proto);

        Assert.True(kept);
        Assert.Equal(IPAddress.Parse("192.168.99.126"), lanSrc);
        Assert.Equal(IPAddress.Parse("3.217.147.217"), dstIp);
        Assert.Equal(443, port);
        Assert.Equal("tcp", proto);
    }

    [Fact]
    public void ClassifyFlow_uses_forward_dport_for_service_not_min()
    {
        // DNS: sport=54938 dport=53. Old Math.Min would have picked 53 here by
        // luck, but the contract is "the port the LAN host connected to" = dport.
        var flow = Parse("ipv4 2 udp 17 2 " +
            "src=192.168.99.126 dst=1.1.1.1 sport=54938 dport=53 packets=1 bytes=75 " +
            "src=1.1.1.1 dst=154.12.104.135 sport=53 dport=54938 packets=1 bytes=299 mark=0 use=1");

        Assert.True(ConntrackSamplerService.ClassifyFlow(flow, Lan, OwnIps, out _, out var dstIp, out var port, out _));
        Assert.Equal(IPAddress.Parse("1.1.1.1"), dstIp);
        Assert.Equal(53, port);  // DNS, not the ephemeral 54938
    }

    [Fact]
    public void ClassifyFlow_media_flow_keeps_the_real_service_port_from_forward_dport()
    {
        // Streaming/QUIC: LAN host connected to a high server port. The forward
        // dport is the truth; Math.Min(sport,dport) would have been a coin flip.
        var flow = Parse("ipv4 2 udp 17 30 " +
            "src=192.168.99.126 dst=52.84.10.20 sport=51000 dport=10920 packets=100 bytes=2000000 " +
            "src=52.84.10.20 dst=154.12.104.135 sport=10920 dport=51000 packets=50 bytes=30000 mark=0 use=1");

        Assert.True(ConntrackSamplerService.ClassifyFlow(flow, Lan, OwnIps, out _, out _, out var port, out _));
        Assert.Equal(10920, port); // forward dport, deterministic
    }

    [Fact]
    public void ClassifyFlow_rejects_when_destination_is_own_ip()
    {
        // A flow whose forward dst is one of our own IPs (host-bound traffic).
        var flow = Parse("ipv4 2 tcp 6 100 ESTABLISHED " +
            "src=192.168.99.126 dst=190.107.150.161 sport=40000 dport=443 packets=1 bytes=500 " +
            "src=190.107.150.161 dst=192.168.99.126 sport=443 dport=40000 packets=1 bytes=500 mark=0 use=1");

        Assert.False(ConntrackSamplerService.ClassifyFlow(flow, Lan, OwnIps, out _, out _, out _, out _));
    }

    [Fact]
    public void ClassifyFlow_rejects_intra_lan_traffic()
    {
        var flow = Parse("ipv4 2 tcp 6 100 ESTABLISHED " +
            "src=192.168.99.126 dst=192.168.99.90 sport=40000 dport=5432 packets=1 bytes=500 " +
            "src=192.168.99.90 dst=192.168.99.126 sport=5432 dport=40000 packets=1 bytes=500 mark=0 use=1");

        Assert.False(ConntrackSamplerService.ClassifyFlow(flow, Lan, OwnIps, out _, out _, out _, out _));
    }

    [Fact]
    public void ClassifyFlow_rejects_rfc1918_destination()
    {
        // Destination in a different private range (e.g. another subnet) — not egress.
        var flow = Parse("ipv4 2 tcp 6 100 ESTABLISHED " +
            "src=192.168.99.126 dst=10.8.0.5 sport=40000 dport=443 packets=1 bytes=500 " +
            "src=10.8.0.5 dst=192.168.99.126 sport=443 dport=40000 packets=1 bytes=500 mark=0 use=1");

        Assert.False(ConntrackSamplerService.ClassifyFlow(flow, Lan, OwnIps, out _, out _, out _, out _));
    }

    [Fact]
    public void ClassifyFlow_rejects_flow_not_sourced_from_lan()
    {
        // Inbound (port-forward) flow: src is external. Counted via the LAN host's
        // own outbound flow elsewhere; here it must be ignored.
        var flow = Parse("ipv4 2 tcp 6 100 ESTABLISHED " +
            "src=8.8.8.8 dst=192.168.99.6 sport=50000 dport=8096 packets=1 bytes=500 " +
            "src=192.168.99.6 dst=8.8.8.8 sport=8096 dport=50000 packets=1 bytes=500 mark=0 use=1");

        Assert.False(ConntrackSamplerService.ClassifyFlow(flow, Lan, OwnIps, out _, out _, out _, out _));
    }

    [Fact]
    public void ClassifyFlow_keeps_genuine_egress()
    {
        var flow = Parse("ipv4 2 tcp 6 100 ESTABLISHED " +
            "src=192.168.99.126 dst=52.1.189.112 sport=33441 dport=443 packets=252 bytes=21491 " +
            "src=52.1.189.112 dst=154.12.104.135 sport=443 dport=33441 packets=246 bytes=19181 mark=0 use=1");

        Assert.True(ConntrackSamplerService.ClassifyFlow(flow, Lan, OwnIps, out var lanSrc, out var dstIp, out var port, out _));
        Assert.Equal(IPAddress.Parse("192.168.99.126"), lanSrc);
        Assert.Equal(IPAddress.Parse("52.1.189.112"), dstIp);
        Assert.Equal(443, port);
    }

    // ── IsPrivate ─────────────────────────────────────────────────────────

    [Theory]
    [InlineData("10.0.0.1", true)]
    [InlineData("172.16.5.5", true)]
    [InlineData("172.31.255.1", true)]
    [InlineData("172.32.0.1", false)]   // just outside 172.16/12
    [InlineData("192.168.99.5", true)]
    [InlineData("169.254.1.1", true)]   // link-local
    [InlineData("100.64.0.1", true)]    // CGNAT
    [InlineData("127.0.0.1", true)]     // loopback
    [InlineData("8.8.8.8", false)]
    [InlineData("154.12.104.135", false)]
    public void IsPrivate_classifies_ranges(string ip, bool expected)
        => Assert.Equal(expected, IpRanges.IsPrivate(IPAddress.Parse(ip)));

    // ── ApplyTopNPerHost ──────────────────────────────────────────────────

    private static ConntrackSamplerService.BucketKey Key(string src, string? dst, int? port = 443)
        => new(IPAddress.Parse(src), dst is null ? null : IPAddress.Parse(dst), "tcp", port);

    private static KeyValuePair<ConntrackSamplerService.BucketKey, ConntrackSamplerService.BucketAgg> B(
        string src, string? dst, long bytes)
        => new(Key(src, dst), new ConntrackSamplerService.BucketAgg(bytes, 0, 1));

    [Fact]
    public void TopN_keeps_all_when_under_limit()
    {
        var input = new Dictionary<ConntrackSamplerService.BucketKey, ConntrackSamplerService.BucketAgg>(
            new[] { B("192.168.99.5", "1.1.1.1", 100), B("192.168.99.5", "8.8.8.8", 200) });

        var outp = ConntrackSamplerService.ApplyTopNPerHost(input, topN: 20);

        Assert.Equal(2, outp.Count);
        Assert.DoesNotContain(outp.Keys, k => k.DstIp is null); // no rollup created
    }

    [Fact]
    public void TopN_folds_tail_into_others_rollup()
    {
        // One host, 4 destinations; keep top 2, fold the other 2 into a NULL-dst row.
        var input = new Dictionary<ConntrackSamplerService.BucketKey, ConntrackSamplerService.BucketAgg>(
            new[]
            {
                B("192.168.99.5", "50.0.0.1", 1000),
                B("192.168.99.5", "50.0.0.2", 800),
                B("192.168.99.5", "50.0.0.3", 30),
                B("192.168.99.5", "50.0.0.4", 12),
            });

        var outp = ConntrackSamplerService.ApplyTopNPerHost(input, topN: 2);

        // 2 top destinations + 1 rollup.
        Assert.Equal(3, outp.Count);
        var rollup = Assert.Single(outp, kv => kv.Key.DstIp is null);
        Assert.Equal(42, rollup.Value.BytesIn);   // 30 + 12
        Assert.Equal(2, rollup.Value.Flows);       // both tail flows counted
        Assert.Null(rollup.Key.Proto);
        Assert.Null(rollup.Key.DstPort);
        // The two kept destinations are the heaviest.
        Assert.Contains(outp.Keys, k => Equals(k.DstIp, IPAddress.Parse("50.0.0.1")));
        Assert.Contains(outp.Keys, k => Equals(k.DstIp, IPAddress.Parse("50.0.0.2")));
    }

    [Fact]
    public void TopN_is_per_host_not_global()
    {
        // Two hosts, 2 dests each; topN=1 → each host keeps 1 + 1 rollup = 4 rows.
        var input = new Dictionary<ConntrackSamplerService.BucketKey, ConntrackSamplerService.BucketAgg>(
            new[]
            {
                B("192.168.99.5", "50.0.0.1", 1000),
                B("192.168.99.5", "50.0.0.2", 10),
                B("192.168.99.6", "50.0.0.3", 2000),
                B("192.168.99.6", "50.0.0.4", 20),
            });

        var outp = ConntrackSamplerService.ApplyTopNPerHost(input, topN: 1);

        Assert.Equal(4, outp.Count);
        Assert.Equal(2, outp.Keys.Count(k => k.DstIp is null)); // one rollup per host
    }

    [Fact]
    public void TopN_zero_means_unlimited()
    {
        var input = new Dictionary<ConntrackSamplerService.BucketKey, ConntrackSamplerService.BucketAgg>(
            new[] { B("192.168.99.5", "50.0.0.1", 1), B("192.168.99.5", "50.0.0.2", 2) });

        var outp = ConntrackSamplerService.ApplyTopNPerHost(input, topN: 0);

        Assert.Same(input, outp); // passthrough
    }
}
