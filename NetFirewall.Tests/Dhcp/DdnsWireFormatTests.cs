using System.Security.Cryptography;
using System.Text;
using NetFirewall.Services.Dhcp;
using Xunit;

namespace NetFirewall.Tests.Dhcp;

/// <summary>
/// Pure wire-format coverage for <see cref="DdnsService"/>: FQDN construction
/// (label-boundary zone matching) and the RFC 2845 TSIG request MAC. The MAC
/// test recomputes the canonical digest input independently — the previous
/// implementation hashed a half-built buffer including unwritten ArrayPool
/// bytes, so every TSIG-signed update failed BADSIG nondeterministically.
/// </summary>
public class DdnsWireFormatTests
{
    // ── BuildFqdn ──────────────────────────────────────────────────────

    [Theory]
    [InlineData("printer", "example.com", "printer.example.com.")]
    [InlineData("host.example.com", "example.com", "host.example.com.")]     // already qualified
    [InlineData("example.com", "example.com", "example.com.")]               // hostname == zone
    [InlineData("myexample.com", "example.com", "myexample.com.example.com.")] // NOT label-aligned → qualify
    [InlineData("printer.", "example.com.", "printer.example.com.")]         // trailing dots normalized
    [InlineData("HOST.EXAMPLE.COM", "example.com", "HOST.EXAMPLE.COM.")]     // case-insensitive zone match
    public void BuildFqdn_ZoneQualification(string hostname, string zone, string expected) =>
        Assert.Equal(expected, DdnsService.BuildFqdn(hostname, zone));

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void BuildFqdn_NoZone_ReturnsHostnameVerbatim(string? zone) =>
        Assert.Equal("printer", DdnsService.BuildFqdn("printer", zone));

    // ── ComputeTsigMac ─────────────────────────────────────────────────

    /// <summary>Canonical DNS wire encoding of a name: length-prefixed
    /// lowercase labels, zero-terminated. Reimplemented here on purpose so the
    /// test validates the production encoding rather than echoing it.</summary>
    private static byte[] WireName(string name)
    {
        using var ms = new MemoryStream();
        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label.ToLowerInvariant());
            ms.WriteByte((byte)bytes.Length);
            ms.Write(bytes);
        }
        ms.WriteByte(0);
        return ms.ToArray();
    }

    [Fact]
    public void ComputeTsigMac_MatchesRfc2845CanonicalDigest()
    {
        // RFC 2845 §3.4: HMAC over (message-without-TSIG ‖ keyname ‖ CLASS=ANY
        // ‖ TTL=0 ‖ algorithm ‖ time48 ‖ fudge ‖ error=0 ‖ otherlen=0).
        var message = Encoding.ASCII.GetBytes("fake-dns-update-message-bytes");
        var key = Encoding.ASCII.GetBytes("super-secret-key-material");
        const string keyName = "Tsig.Key.Example";
        const string algorithm = "hmac-sha256";
        // Locals (not consts) so the byte-casts below aren't constant-folded
        // into CS0221 range errors.
        long timeSigned = 1_700_000_000L;
        ushort fudge = 300;

        var expectedInput = new List<byte>();
        expectedInput.AddRange(message);
        expectedInput.AddRange(WireName(keyName));
        expectedInput.AddRange(new byte[] { 0x00, 0xFF });             // CLASS = ANY (255)
        expectedInput.AddRange(new byte[] { 0, 0, 0, 0 });             // TTL = 0
        expectedInput.AddRange(WireName(algorithm));
        expectedInput.AddRange(new byte[]
        {
            (byte)(timeSigned >> 40), (byte)(timeSigned >> 32), (byte)(timeSigned >> 24),
            (byte)(timeSigned >> 16), (byte)(timeSigned >> 8), (byte)timeSigned
        });
        expectedInput.AddRange(new byte[] { (byte)(fudge >> 8), (byte)fudge });
        expectedInput.AddRange(new byte[] { 0, 0 });                   // Error = 0
        expectedInput.AddRange(new byte[] { 0, 0 });                   // Other len = 0

        using var hmac = new HMACSHA256(key);
        var expected = hmac.ComputeHash(expectedInput.ToArray());

        var actual = DdnsService.ComputeTsigMac(message, keyName, algorithm, key, timeSigned, fudge);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ComputeTsigMac_IsDeterministic_ForSameInputs()
    {
        var message = new byte[] { 1, 2, 3 };
        var key = new byte[] { 9, 9, 9 };

        var a = DdnsService.ComputeTsigMac(message, "k.example", "hmac-sha256", key, 1000, 300);
        var b = DdnsService.ComputeTsigMac(message, "k.example", "hmac-sha256", key, 1000, 300);

        Assert.Equal(a, b);
    }

    [Fact]
    public void ComputeTsigMac_ChangesWithMessage()
    {
        var key = new byte[] { 9, 9, 9 };

        var a = DdnsService.ComputeTsigMac(new byte[] { 1 }, "k.example", "hmac-sha256", key, 1000, 300);
        var b = DdnsService.ComputeTsigMac(new byte[] { 2 }, "k.example", "hmac-sha256", key, 1000, 300);

        Assert.NotEqual(a, b);
    }

    [Theory]
    [InlineData("hmac-sha256", 32)]
    [InlineData("hmac-sha1", 20)]
    [InlineData("hmac-sha512", 64)]
    [InlineData("hmac-md5.sig-alg.reg.int", 16)]
    public void ComputeTsigMac_AlgorithmSelectsDigestLength(string algorithm, int expectedLength)
    {
        var mac = DdnsService.ComputeTsigMac(new byte[] { 1 }, "k", algorithm, new byte[] { 2 }, 0, 300);

        Assert.Equal(expectedLength, mac.Length);
    }
}
