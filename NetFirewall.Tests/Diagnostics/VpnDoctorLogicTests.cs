using NetFirewall.Models.Diagnostics;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Diagnostics.Vpn;
using NetFirewall.Services.Diagnostics.Vpn.Checks;

namespace NetFirewall.Tests.Diagnostics;

/// <summary>
/// The pure decision logic behind the VPN doctor: the probe verdict, the
/// issued-config diff, and the two ruleset predicates. Each case is one of the
/// failures that cost a manual round on tekium.
/// </summary>
public class VpnDoctorLogicTests
{
    private static WgServer Server(string address = "192.168.3.2/32", int listen = 0, bool tableOff = true, int? mtu = null) => new()
    {
        Id = Guid.NewGuid(), Name = "wg0", Mode = "server", PrivateKey = "P", PublicKey = "OURKEY=",
        AddressCidr = address, ListenPort = listen, TableOff = tableOff, Mtu = mtu, Enabled = true,
    };

    private static WgPeer Upstream(string key = "THEIRKEY=", string? endpoint = "73.213.125.58:51820", params string[] allowed) => new()
    {
        Id = Guid.NewGuid(), Name = "usa", Role = "upstream", Enabled = true,
        PublicKey = key, Endpoint = endpoint,
        AllowedIps = allowed.Length == 0 ? ["0.0.0.0/0"] : allowed,
    };

    // ───────────────────────── probe verdicts ─────────────────────────

    private static PingResult Ping(int received, string? error = null) =>
        new("1.1.1.1", "1.1.1.1", "fwmark 0x500", 3, received, received == 0 ? 100 : 0, null, null, null, Array.Empty<PingReply>(), "", error);

    [Fact]
    public void Probe_RepliesArrived_IsOk()
    {
        var (verdict, why) = VpnDoctorService.Classify(Ping(3), null, 100, 500, 100, 400, 1280, "wg0", "1.1.1.1");
        Assert.Equal("ok", verdict);
        Assert.Contains("end to end", why);
    }

    [Fact]
    public void Probe_TxGrowsRxFlat_BlamesTheRemoteEnd()
    {
        // Exactly yesterday's outage: handshake fine, our source address not in their AllowedIPs.
        var (verdict, why) = VpnDoctorService.Classify(Ping(0), Ping(0), 1000, 1300, 500, 500, 1280, "wg0", "1.1.1.1");
        Assert.Equal("remote-drops", verdict);
        Assert.Contains("AllowedIPs", why);
        Assert.Contains("issued config", why);
    }

    [Fact]
    public void Probe_NothingLeft_BlamesLocalRouting()
    {
        var (verdict, why) = VpnDoctorService.Classify(Ping(0), null, 1000, 1000, 500, 500, 1280, "wg0", "1.1.1.1");
        Assert.Equal("local-routing", verdict);
        Assert.Contains("0x500", why);
        Assert.Contains("table 'wg0'", why);
    }

    [Fact]
    public void Probe_BothCountersGrewButNoReplies_BlamesTheLocalInputPath()
    {
        // The far end answered (rx grew) and our probe did leave (tx grew), yet ping
        // saw nothing: the replies died between the tunnel and the socket.
        var (verdict, why) = VpnDoctorService.Classify(Ping(0), Ping(0), 1000, 1300, 500, 900, 1280, "wg0", "1.1.1.1");
        Assert.Equal("replies-dropped", verdict);
        Assert.Contains("rp_filter", why);
    }

    [Fact]
    public void Probe_TxFlatWhileRxMoves_IsStillLocalRouting()
    {
        // Keepalives from the peer can move rx on their own; what matters is that
        // nothing of ours entered the tunnel.
        var (verdict, _) = VpnDoctorService.Classify(Ping(0), Ping(0), 1000, 1000, 500, 900, 1280, "wg0", "1.1.1.1");
        Assert.Equal("local-routing", verdict);
    }

    [Fact]
    public void Probe_NoMarkAndNoMovement_IsInconclusive()
    {
        var (verdict, _) = VpnDoctorService.Classify(Ping(0), Ping(0), 1000, 1000, 500, 500, 0, "wg0", "1.1.1.1");
        Assert.Equal("inconclusive", verdict);
    }

    // ───────────────────────── issued-config diff ─────────────────────────

    [Fact]
    public void Compare_AddressMismatch_IsAFailWithBothValues()
    {
        var issued = new WgQuickConfig("192.168.3.2/32", "192.168.3.1", null, null, null,
            [new WgQuickPeer("THEIRKEY=", "73.213.125.58:51820", ["0.0.0.0/0"], null)]);
        var upstream = Upstream();

        var r = VpnDoctorService.Compare(issued, Server(address: "192.168.3.3/32"), [upstream]);

        var addr = r.Differences.Single(d => d.Field == "Address");
        Assert.Equal(DiagCheckStatus.Fail, addr.Severity);
        Assert.Equal("192.168.3.2/32", addr.Issued);
        Assert.Equal("192.168.3.3/32", addr.Ours);
        Assert.Contains("silently drops", addr.Note);
        Assert.Equal(DiagCheckStatus.Fail, r.Overall);
    }

    [Fact]
    public void Compare_EverythingMatches_IsPass()
    {
        var issued = new WgQuickConfig("192.168.3.2/32", null, null, null, null,
            [new WgQuickPeer("THEIRKEY=", "73.213.125.58:51820", ["0.0.0.0/0"], null)]);

        var r = VpnDoctorService.Compare(issued, Server(), [Upstream()]);

        Assert.Equal(DiagCheckStatus.Pass, r.Overall);
        Assert.All(r.Differences, d => Assert.Equal(DiagCheckStatus.Pass, d.Severity));
    }

    [Fact]
    public void Compare_WrongServerKey_FailsTheHandshakeCheck()
    {
        var issued = new WgQuickConfig("192.168.3.2/32", null, null, null, null,
            [new WgQuickPeer("REALSERVERKEY=", "73.213.125.58:51820", ["0.0.0.0/0"], null)]);

        var r = VpnDoctorService.Compare(issued, Server(), [Upstream(key: "STALEKEY=")]);

        var key = r.Differences.Single(d => d.Field == "Peer public key");
        Assert.Equal(DiagCheckStatus.Fail, key.Severity);
        Assert.Contains("handshake cannot complete", key.Note);
    }

    [Fact]
    public void Compare_BareAddressAndSlash32_AreTheSameHost()
    {
        var issued = new WgQuickConfig("192.168.3.2", null, null, null, null, Array.Empty<WgQuickPeer>());
        var r = VpnDoctorService.Compare(issued, Server(address: "192.168.3.2/32"), Array.Empty<WgPeer>());
        Assert.Equal(DiagCheckStatus.Pass, r.Differences.Single(d => d.Field == "Address").Severity);
    }

    [Fact]
    public void Compare_DifferentEndpoint_IsOnlyAWarning()
    {
        var issued = new WgQuickConfig("192.168.3.2/32", null, null, null, null,
            [new WgQuickPeer("THEIRKEY=", "vpn.example.com:51820", ["0.0.0.0/0"], null)]);

        var r = VpnDoctorService.Compare(issued, Server(), [Upstream()]);

        Assert.Equal(DiagCheckStatus.Warn, r.Differences.Single(d => d.Field == "Endpoint").Severity);
        Assert.Equal(DiagCheckStatus.Warn, r.Overall);
    }

    // ───────────────────────── ruleset predicates ─────────────────────────

    [Theory]
    // The live tekium catch-all: no match at all before the mark.
    [InlineData("meta mark set 0x00000500 return comment \"Specific hosts → wg0 (VPN)\"", true)]
    [InlineData("ip saddr { 192.168.99.60, 192.168.99.66 } meta mark set 0x00000500 return", false)]
    [InlineData("ip daddr 192.168.1.0/24 meta mark set 0x00000500 return", false)]
    [InlineData("iifname \"ens192\" ct state new ct mark set 0x00000100", false)]
    [InlineData("ct direction reply ct mark != 0x00000000 meta mark set ct mark return", false)]
    [InlineData("ip protocol tcp meta mark set 0x100 return", false)]
    public void MangleCatchAll_DetectsUnconstrainedMarkRules(string line, bool unconstrained)
    {
        // `ct mark set` lines have no "meta mark set" at all — guard the ones that do.
        if (!line.Contains("meta mark set", StringComparison.Ordinal))
        {
            Assert.False(unconstrained);
            return;
        }
        Assert.Equal(unconstrained, MangleCatchAllCheck.IsUnconstrained(line));
    }

    [Theory]
    [InlineData("ip saddr 192.168.99.0/24 oif 7 masquerade", true)]
    [InlineData("iif 5 oifname \"ens256\" accept", true)]
    [InlineData("ip saddr 192.168.99.0/24 oifname \"wg0\" masquerade", false)]
    [InlineData("iifname \"wg0\" oifname \"ens256\" accept", false)]
    [InlineData("iif \"lo\" accept", false)]
    public void StaleIndexMatch_FlagsOnlyNumericInterfaceMatches(string line, bool flagged) =>
        Assert.Equal(flagged, MasqueradeCheck.IndexMatchRx().IsMatch(line));

    [Theory]
    [InlineData("192.168.3.2/32", "192.168.3.2/32", true)]
    [InlineData("192.168.3.2", "192.168.3.2/32", true)]
    [InlineData("192.168.3.3/32", "192.168.3.2/32", false)]
    [InlineData("192.168.3.2/24", "192.168.3.2/32", false)]
    public void InterfaceAddress_ComparesHostAddressesSensibly(string live, string configured, bool same) =>
        Assert.Equal(same, InterfaceAddressCheck.SameAddress(live, configured));
}
