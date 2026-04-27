using NetFirewall.Web.Auth.Bootstrap;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// In-memory tests for the singleton bootstrap-token store. The store is
/// trivial but guards privilege escalation: a wrong, replayed, or post-consume
/// token must NOT match.
/// </summary>
public class BootstrapTokenStoreTests
{
    [Fact]
    public void IsActive_FalseUntilIssue_TrueAfter_FalseAfterConsume()
    {
        var s = new BootstrapTokenStore();
        Assert.False(s.IsActive);

        s.Issue("ABC123");
        Assert.True(s.IsActive);

        s.Consume();
        Assert.False(s.IsActive);
    }

    [Fact]
    public void Verify_ExactMatch_ReturnsTrue()
    {
        var s = new BootstrapTokenStore();
        s.Issue("ABC123");
        Assert.True(s.Verify("ABC123"));
    }

    [Fact]
    public void Verify_WrongToken_ReturnsFalse()
    {
        var s = new BootstrapTokenStore();
        s.Issue("ABC123");
        Assert.False(s.Verify("WRONG"));
    }

    [Fact]
    public void Verify_NoActiveToken_AlwaysFalse()
    {
        var s = new BootstrapTokenStore();
        Assert.False(s.Verify("anything"));
    }

    [Theory]
    [InlineData("")]
    [InlineData(null)]
    public void Verify_EmptyOrNull_ReturnsFalse(string? input)
    {
        var s = new BootstrapTokenStore();
        s.Issue("ABC123");
        Assert.False(s.Verify(input!));
    }

    [Fact]
    public void Verify_AfterConsume_ReturnsFalseEvenForCorrectToken()
    {
        var s = new BootstrapTokenStore();
        s.Issue("ABC123");
        Assert.True(s.Verify("ABC123"));

        s.Consume();

        Assert.False(s.Verify("ABC123"));
    }

    [Fact]
    public void Issue_TwiceWithoutConsume_Throws()
    {
        var s = new BootstrapTokenStore();
        s.Issue("FIRST");
        Assert.Throws<InvalidOperationException>(() => s.Issue("SECOND"));
    }

    [Fact]
    public void CurrentToken_ReturnsTokenWhenActive_NullOtherwise()
    {
        var s = new BootstrapTokenStore();
        Assert.Null(s.CurrentToken);
        s.Issue("XYZ");
        Assert.Equal("XYZ", s.CurrentToken);
        s.Consume();
        Assert.Null(s.CurrentToken);
    }
}
