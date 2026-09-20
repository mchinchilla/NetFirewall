using NetFirewall.Services.Diagnostics;

namespace NetFirewall.Tests.Diagnostics;

public class DiagnosticInputValidatorTests
{
    private readonly DiagnosticInputValidator _v = new();

    [Theory]
    [InlineData("1.1.1.1", "1.1.1.1")]
    [InlineData(" 192.168.99.60 ", "192.168.99.60")]
    [InlineData("2606:4700:4700::1111", "2606:4700:4700::1111")]
    [InlineData("example.com", "example.com")]
    [InlineData("a-b.c1.example", "a-b.c1.example")]
    [InlineData("localhost", "localhost")]
    public void TryHost_AcceptsLiteralsAndHostnames(string input, string expected)
    {
        Assert.True(_v.TryHost(input, out var normalized, out var error), error);
        Assert.Equal(expected, normalized);
    }

    [Theory]
    [InlineData("")]
    [InlineData("-c")]                 // would be read as a flag by ping
    [InlineData("-n 1.1.1.1")]
    [InlineData("1.1.1.1; rm -rf /")]
    [InlineData("$(id)")]
    [InlineData("1.2.3")]              // IPAddress.TryParse shorthand → 1.2.0.3, refuse
    [InlineData("fe80::1%eth0")]       // zone id
    [InlineData("host name")]
    [InlineData("-example.com")]
    [InlineData("exa_mple.com")]
    public void TryHost_RejectsAnythingThatIsNotAHostOrAddress(string input)
    {
        Assert.False(_v.TryHost(input, out _, out var error));
        Assert.False(string.IsNullOrEmpty(error));
    }

    [Fact]
    public void TryHost_RejectsOverlongHostname()
    {
        var label = new string('a', 63);
        var tooLong = string.Join('.', Enumerable.Repeat(label, 5)); // 319 chars
        Assert.False(_v.TryHost(tooLong, out _, out _));
    }

    [Theory]
    [InlineData("192.168.99.0/24", "192.168.99.0/24")]
    [InlineData("10.0.0.1", "10.0.0.1")]
    [InlineData("::/0", "::/0")]
    public void TryCidrOrIp_Accepts(string input, string expected)
    {
        Assert.True(_v.TryCidrOrIp(input, out var n, out var e), e);
        Assert.Equal(expected, n);
    }

    [Theory]
    [InlineData("192.168.99.0/33")]
    [InlineData("192.168.99.0/x")]
    [InlineData("lan")]
    [InlineData("-1.2.3.4/32")]
    public void TryCidrOrIp_Rejects(string input) =>
        Assert.False(_v.TryCidrOrIp(input, out _, out _));

    [Fact]
    public void TryInterfaceName_RequiresKernelCharsetAndAllowlist()
    {
        var allowed = new HashSet<string>(StringComparer.Ordinal) { "ens192", "wg0" };

        Assert.True(_v.TryInterfaceName("wg0", allowed, out var n, out _));
        Assert.Equal("wg0", n);
        Assert.False(_v.TryInterfaceName("eth0", allowed, out _, out var unknown));     // not in allowlist
        Assert.Contains("Unknown", unknown);
        Assert.False(_v.TryInterfaceName("wg0;id", allowed, out _, out _));           // charset
        Assert.False(_v.TryInterfaceName("averyveryverylongname", allowed, out _, out _)); // > 15
        Assert.False(_v.TryInterfaceName("", allowed, out _, out _));
    }

    [Theory]
    [InlineData("0x500", 1280)]
    [InlineData("1280", 1280)]
    [InlineData("0x1", 1)]
    [InlineData("", 0)]      // no mark
    [InlineData(null, 0)]
    public void TryFwmark_Accepts(string? input, long expected)
    {
        Assert.True(_v.TryFwmark(input, out var mark, out var e), e);
        Assert.Equal(expected, mark);
    }

    [Theory]
    [InlineData("0")]
    [InlineData("0x100000000")]  // > 32 bit
    [InlineData("0xZZ")]
    [InlineData("500;")]
    [InlineData("-1")]
    public void TryFwmark_Rejects(string input) =>
        Assert.False(_v.TryFwmark(input, out _, out _));

    [Fact]
    public void TryProto_And_TryPort()
    {
        Assert.True(_v.TryProto("TCP", out var p, out _)); Assert.Equal("tcp", p);
        Assert.True(_v.TryProto("", out var none, out _)); Assert.Equal("", none);
        Assert.False(_v.TryProto("sctp", out _, out _));
        Assert.True(_v.TryPort(53, out var port, out _)); Assert.Equal(53, port);
        Assert.True(_v.TryPort(null, out _, out _));
        Assert.False(_v.TryPort(0, out _, out _));
        Assert.False(_v.TryPort(70000, out _, out _));
    }

    [Fact]
    public void RedactWgConfig_StripsPrivateAndPresharedKeys_KeepsTheRest()
    {
        const string cfg = """
            [Interface]
            PrivateKey = cGHUGTxppNGtksPR/j9jWc18KuQ3cKf1z7H7j3FSeX8=
            Address = 192.168.3.2/32
            DNS = 192.168.3.1

            [Peer]
            PublicKey = KBcsMr88nIPsoKJD4dSw1fvNtjDUdhchkhHKJU4LgH4=
            presharedkey=abc123
            AllowedIPs = 0.0.0.0/0
            Endpoint = 73.213.125.58:51820
            """;

        var redacted = _v.RedactWgConfig(cfg);

        Assert.DoesNotContain("cGHUGTxppNGtksPR", redacted);
        Assert.DoesNotContain("abc123", redacted);
        Assert.Contains("PrivateKey = <redacted>", redacted);
        Assert.Contains("Address = 192.168.3.2/32", redacted);
        Assert.Contains("PublicKey = KBcsMr88nIPsoKJD4dSw1fvNtjDUdhchkhHKJU4LgH4=", redacted);
        Assert.Contains("Endpoint = 73.213.125.58:51820", redacted);
    }
}
