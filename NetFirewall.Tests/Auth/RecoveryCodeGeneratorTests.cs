using NetFirewall.Services.Auth;
using Xunit;

namespace NetFirewall.Tests.Auth;

public class RecoveryCodeGeneratorTests
{
    private readonly RecoveryCodeGenerator _gen = new();

    private const string CrockfordAlphabet = "23456789ABCDEFGHJKMNPQRSTVWXYZ";

    [Fact]
    public void Generate_ReturnsRequestedCount()
    {
        Assert.Equal(10, _gen.Generate().Count);
        Assert.Equal(5, _gen.Generate(5).Count);
        Assert.Single(_gen.Generate(1));
        Assert.Equal(50, _gen.Generate(50).Count);
    }

    [Fact]
    public void Generate_EmitsExpectedFormat()
    {
        foreach (var code in _gen.Generate(20))
        {
            // "XXXXX-XXXXX" — 11 chars, dash at position 5.
            Assert.Equal(11, code.Length);
            Assert.Equal('-', code[5]);

            // Every other char is in the Crockford alphabet (no 0/O/1/I/L/U).
            for (var i = 0; i < code.Length; i++)
            {
                if (i == 5) continue;
                Assert.Contains(code[i], CrockfordAlphabet);
            }
        }
    }

    [Fact]
    public void Generate_ProducesUnambiguousAlphabet()
    {
        // Sanity check: confirm we never emit characters that are visually
        // confusable when transcribed (0/O/1/I/L/U) — the whole point of
        // Crockford base32.
        var bigBatch = string.Join("", _gen.Generate(50));
        foreach (var bad in "01ILOU")
            Assert.DoesNotContain(bad, bigBatch);
    }

    [Fact]
    public void Generate_ProducesDistinctCodesAcrossBatch()
    {
        var batch = _gen.Generate(50);
        Assert.Equal(batch.Count, batch.Distinct().Count());
    }

    [Fact]
    public void Generate_ProducesDifferentBatchesAcrossInvocations()
    {
        var a = _gen.Generate(10);
        var b = _gen.Generate(10);
        Assert.Empty(a.Intersect(b)); // ~50 bits each — collision is astronomically unlikely
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(51)]
    [InlineData(int.MaxValue)]
    public void Generate_RejectsCountOutOfRange(int count)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => _gen.Generate(count));
    }
}
