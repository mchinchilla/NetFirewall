using NetFirewall.Services.Auth;
using Xunit;

namespace NetFirewall.Tests.Auth;

public class Argon2PasswordHasherTests
{
    private readonly Argon2PasswordHasher _hasher = new();

    [Fact]
    public async Task HashAsync_ProducesEncodedFormatWithCurrentParameters()
    {
        var encoded = await _hasher.HashAsync("hunter2");

        Assert.StartsWith("$argon2id$v=19$", encoded);
        Assert.Contains("m=65536,t=3,p=4", encoded);
        // 5 sections separated by '$': argon2id, v=19, params, salt, hash
        Assert.Equal(6, encoded.Split('$').Length);
    }

    [Fact]
    public async Task HashAsync_ProducesDifferentOutputsForSamePassword()
    {
        var a = await _hasher.HashAsync("hunter2");
        var b = await _hasher.HashAsync("hunter2");
        Assert.NotEqual(a, b); // random salt
    }

    [Fact]
    public async Task VerifyAsync_AcceptsCorrectPassword()
    {
        var encoded = await _hasher.HashAsync("hunter2");
        var result = await _hasher.VerifyAsync("hunter2", encoded);

        Assert.True(result.Matches);
        Assert.False(result.NeedsRehash);
    }

    [Fact]
    public async Task VerifyAsync_RejectsWrongPassword()
    {
        var encoded = await _hasher.HashAsync("hunter2");
        var result = await _hasher.VerifyAsync("hunter3", encoded);

        Assert.False(result.Matches);
        Assert.False(result.NeedsRehash);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not-a-hash")]
    [InlineData("$argon2id$")]
    [InlineData("$bcrypt$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA")]   // wrong algorithm
    [InlineData("$argon2id$v=18$m=65536,t=3,p=4$c2FsdA$aGFzaA")] // wrong version
    [InlineData("$argon2id$v=19$m=65536,t=3,p=4$@@@$###")]       // bad base64
    public async Task VerifyAsync_ReturnsFalseOnMalformedHash(string encoded)
    {
        var result = await _hasher.VerifyAsync("anything", encoded);
        Assert.False(result.Matches);
        Assert.False(result.NeedsRehash);
    }

    [Fact]
    public async Task VerifyAsync_FlagsNeedsRehashWhenStoredParamsAreWeaker()
    {
        // Build a legit hash but with weaker params than the current defaults,
        // by hand-crafting the encoded form via a separate (low-cost) Argon2
        // computation to keep the test fast.
        const string password = "hunter2";
        var salt = System.Text.Encoding.UTF8.GetBytes("0123456789abcdef0123456789abcdef");
        using var argon2 = new Konscious.Security.Cryptography.Argon2id(System.Text.Encoding.UTF8.GetBytes(password))
        {
            Salt = salt,
            MemorySize = 8 * 1024, // 8 MB — well below current 64 MB default
            Iterations = 2,
            DegreeOfParallelism = 2
        };
        var hashBytes = argon2.GetBytes(32);
        var encoded =
            $"$argon2id$v=19$m=8192,t=2,p=2$" +
            $"{Convert.ToBase64String(salt).TrimEnd('=')}$" +
            $"{Convert.ToBase64String(hashBytes).TrimEnd('=')}";

        var result = await _hasher.VerifyAsync(password, encoded);

        Assert.True(result.Matches);
        Assert.True(result.NeedsRehash); // params differ from current → caller should rehash
    }

    [Fact]
    public async Task HashAsync_RespectsCancellation()
    {
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => _hasher.HashAsync("hunter2", cts.Token));
    }
}
