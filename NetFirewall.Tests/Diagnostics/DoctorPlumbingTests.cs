using System.Net;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Diagnostics;
using NetFirewall.Services.Diagnostics.Doctors;
using NetFirewall.Services.Diagnostics.Doctors.Dhcp;
using NetFirewall.Services.Diagnostics.Doctors.Dns;

namespace NetFirewall.Tests.Diagnostics;

/// <summary>
/// The shared doctor runner (used by all four doctors) and the pure logic the
/// WAN/DHCP/DNS checks are built on.
/// </summary>
public class DoctorPlumbingTests
{
    private sealed record Ctx(string Name);

    private sealed class FakeCheck(string id, Func<Ctx, CancellationToken, Task<IReadOnlyList<DiagCheck>>> body) : IDoctorCheck<Ctx>
    {
        public string Id => id;
        public string Category => "Test";
        public Task<IReadOnlyList<DiagCheck>> RunAsync(Ctx ctx, CancellationToken ct) => body(ctx, ct);
    }

    private static DoctorRunner Runner(int perCheckSeconds = 1) =>
        new(Options.Create(new DiagnosticsOptions { CheckTimeoutSeconds = perCheckSeconds, DoctorParallelism = 4 }),
            NullLogger<DoctorRunner>.Instance);

    [Fact]
    public async Task Runner_CollectsEveryRow_AndStampsDurations()
    {
        var checks = new IDoctorCheck<Ctx>[]
        {
            new FakeCheck("a", (_, _) => Task.FromResult<IReadOnlyList<DiagCheck>>([DiagCheck.Pass("a", "Test", "A", "ok")])),
            new FakeCheck("b", (_, _) => Task.FromResult<IReadOnlyList<DiagCheck>>(
                [DiagCheck.Warn("b1", "Test", "B1", "hmm"), DiagCheck.Fail("b2", "Test", "B2", "bad")])),
        };

        var report = await Runner().RunAsync("t", "subject", new Ctx("x"), checks);

        Assert.Equal(3, report.Checks.Count);
        Assert.Equal(1, report.PassCount);
        Assert.Equal(1, report.WarnCount);
        Assert.Equal(1, report.FailCount);
        Assert.Equal(DiagCheckStatus.Fail, report.Overall);
        Assert.Equal(DiagRunStatus.Fail, report.RunStatus);
        Assert.Equal("subject", report.Subject);
        Assert.All(report.Checks, c => Assert.True(c.DurationMs >= 0));
    }

    [Fact]
    public async Task Runner_SlowCheckBecomesSkip_AndDoesNotSinkTheReport()
    {
        var checks = new IDoctorCheck<Ctx>[]
        {
            new FakeCheck("fast", (_, _) => Task.FromResult<IReadOnlyList<DiagCheck>>([DiagCheck.Pass("fast", "Test", "Fast", "ok")])),
            new FakeCheck("slow", async (_, ct) => { await Task.Delay(TimeSpan.FromSeconds(30), ct); return [DiagCheck.Pass("slow", "Test", "Slow", "never")]; }),
        };

        var report = await Runner(perCheckSeconds: 1).RunAsync("t", "s", new Ctx("x"), checks);

        Assert.Equal(2, report.Checks.Count);
        var slow = report.Checks.Single(c => c.Id == "slow");
        Assert.Equal(DiagCheckStatus.Skip, slow.Status);
        Assert.Contains("Timed out", slow.Summary);
        Assert.Equal(DiagCheckStatus.Pass, report.Overall);   // a skip never worsens the verdict
    }

    [Fact]
    public async Task Runner_ThrowingCheckBecomesSkip_WithTheReason()
    {
        var checks = new IDoctorCheck<Ctx>[] { new FakeCheck("boom", (_, _) => throw new InvalidOperationException("no such table")) };

        var report = await Runner().RunAsync("t", "s", new Ctx("x"), checks);

        var row = Assert.Single(report.Checks);
        Assert.Equal(DiagCheckStatus.Skip, row.Status);
        Assert.Contains("no such table", row.Summary);
    }

    [Fact]
    public async Task Runner_AllSkips_IsASkipOverall_ReportedAsOk()
    {
        var checks = new IDoctorCheck<Ctx>[] { new FakeCheck("s", (_, _) => Task.FromResult<IReadOnlyList<DiagCheck>>([DiagCheck.Skip("s", "Test", "S", "n/a")])) };

        var report = await Runner().RunAsync("t", "s", new Ctx("x"), checks);

        Assert.Equal(DiagCheckStatus.Skip, report.Overall);
        Assert.Equal(DiagRunStatus.Ok, report.RunStatus);
    }

    // ───────────────────────── DHCP pure logic ─────────────────────────

    [Theory]
    [InlineData("192.168.99.10", "192.168.99.0", 24, true)]
    [InlineData("192.168.1.10", "192.168.99.0", 24, false)]
    [InlineData("10.0.5.1", "10.0.0.0", 8, true)]
    [InlineData("10.1.0.1", "10.0.0.0", 16, false)]
    public void Dhcp_SameNetwork_MatchesTheScope(string addr, string network, int prefix, bool expected) =>
        Assert.Equal(expected, DhcpSubnetSanityCheck.SameNetwork(IPAddress.Parse(addr), IPAddress.Parse(network), prefix));

    [Theory]
    [InlineData("192.168.99.100", "192.168.99.199", 100)]
    [InlineData("192.168.99.100", "192.168.99.100", 1)]
    [InlineData("192.168.99.200", "192.168.99.100", 0)]   // inverted range
    public void Dhcp_PoolCapacity(string start, string end, long expected) =>
        Assert.Equal(expected, DhcpPoolCheck.RangeSize(IPAddress.Parse(start), IPAddress.Parse(end)));

    [Fact]
    public void Dhcp_CidrParsing_RejectsJunk()
    {
        Assert.True(DhcpSubnetSanityCheck.TryParseCidr("192.168.99.0/24", out var net, out var prefix));
        Assert.Equal("192.168.99.0", net.ToString());
        Assert.Equal(24, prefix);

        Assert.False(DhcpSubnetSanityCheck.TryParseCidr("192.168.99.0", out _, out _));
        Assert.False(DhcpSubnetSanityCheck.TryParseCidr("192.168.99.0/33", out _, out _));
        Assert.False(DhcpSubnetSanityCheck.TryParseCidr("", out _, out _));
    }

    // ───────────────────────── DNS wire format ─────────────────────────

    [Fact]
    public void Dns_QueryIsAWellFormedARecordRequest()
    {
        var query = DnsDoctorContext.BuildQuery("example.com", out var id);

        Assert.Equal(id >> 8, query[0]);
        Assert.Equal(id & 0xFF, query[1]);
        Assert.Equal(0x01, query[2]);                       // recursion desired
        Assert.Equal(1, (query[4] << 8) | query[5]);        // one question
        // QNAME: 7"example" 3"com" 0
        Assert.Equal(7, query[12]);
        Assert.Equal("example", System.Text.Encoding.ASCII.GetString(query, 13, 7));
        Assert.Equal(3, query[20]);
        Assert.Equal("com", System.Text.Encoding.ASCII.GetString(query, 21, 3));
        Assert.Equal(0, query[24]);
        Assert.Equal([0x00, 0x01, 0x00, 0x01], query[25..]); // QTYPE A, QCLASS IN
    }

    [Fact]
    public void Dns_ReplyParsing_ReadsRcodeAndAnswerCount()
    {
        static byte[] Reply(ushort id, int rcode, int answers) =>
        [
            (byte)(id >> 8), (byte)(id & 0xFF),
            0x81, (byte)(0x80 | rcode),
            0x00, 0x01,
            (byte)(answers >> 8), (byte)(answers & 0xFF),
            0x00, 0x00, 0x00, 0x00,
        ];

        Assert.Equal(("NOERROR", 2), DnsDoctorContext.ParseReply(Reply(1234, 0, 2), 1234));
        Assert.Equal(("SERVFAIL", 0), DnsDoctorContext.ParseReply(Reply(1234, 2, 0), 1234));
        Assert.Equal(("NXDOMAIN", 0), DnsDoctorContext.ParseReply(Reply(1234, 3, 0), 1234));
        Assert.Equal(("REFUSED", 0), DnsDoctorContext.ParseReply(Reply(1234, 5, 0), 1234));
        // A reply for someone else's query must never be read as our answer.
        Assert.Equal(("MISMATCH", 0), DnsDoctorContext.ParseReply(Reply(9999, 0, 1), 1234));
        Assert.Equal(("MALFORMED", 0), DnsDoctorContext.ParseReply([0x01, 0x02], 1234));
    }
}
