using NetFirewall.Web.Helpers;

namespace NetFirewall.Tests.Web;

/// <summary>
/// The sidebar lit two items at once: "All tools" is /Diagnostics, every other
/// Diagnostics page is /Diagnostics/<something>, and prefix matching made the
/// section index match its own children.
/// </summary>
public class NavActiveStateTests
{
    private static readonly string?[] DiagGroup =
    [
        "/Diagnostics", "/Diagnostics/Vpn", "/Diagnostics/Wan", "/Diagnostics/Dhcp", "/Diagnostics/Dns",
        "/Diagnostics/Ping", "/Diagnostics/trace", "/Diagnostics/capture", "/Diagnostics/History",
    ];

    [Fact]
    public void SectionIndex_GoesDark_WhenAChildPageIsOpen()
    {
        Assert.False(NavActiveState.IsActive("/Diagnostics/Vpn", "/Diagnostics", DiagGroup));
        Assert.True(NavActiveState.IsActive("/Diagnostics/Vpn", "/Diagnostics/Vpn", DiagGroup));
    }

    [Fact]
    public void SectionIndex_IsActive_OnItsOwnPage()
    {
        Assert.True(NavActiveState.IsActive("/Diagnostics", "/Diagnostics", DiagGroup));
        Assert.False(NavActiveState.IsActive("/Diagnostics", "/Diagnostics/Vpn", DiagGroup));
    }

    [Fact]
    public void ExactlyOneLinkIsActive_ForEveryPageInTheGroup()
    {
        foreach (var page in DiagGroup)
        {
            var lit = DiagGroup.Count(h => NavActiveState.IsActive(page, h, DiagGroup));
            Assert.True(lit == 1, $"{page} lit {lit} sidebar items, expected 1");
        }
    }

    [Fact]
    public void AChildRouteKeepsItsOwnLinkActive()
    {
        // A drill-down under a leaf still belongs to that leaf.
        Assert.True(NavActiveState.IsActive("/Diagnostics/History/abc", "/Diagnostics/History", DiagGroup));
        Assert.False(NavActiveState.IsActive("/Diagnostics/History/abc", "/Diagnostics", DiagGroup));
    }

    [Theory]
    [InlineData("/Firewall/Qos", "/Firewall/Qos", true)]
    [InlineData("/Firewall/Qos/7/Classes", "/Firewall/Qos", true)]
    [InlineData("/Firewall/QosOther", "/Firewall/Qos", false)]   // sibling, not a child
    [InlineData("/", "/", true)]
    [InlineData("/Dashboard", "/", false)]                        // root must not match everything
    public void Matches_UsesSegmentBoundaries(string path, string href, bool expected) =>
        Assert.Equal(expected, NavActiveState.Matches(path, href));

    [Theory]
    [InlineData("#")]
    [InlineData("")]
    [InlineData(null)]
    public void NonLinks_AreNeverActive(string? href) =>
        Assert.False(NavActiveState.Matches("/Diagnostics", href));

    [Fact]
    public void WithoutAGroup_TheLinkOwnsItsWholeSubtree()
    {
        // Standalone links (Dashboard, terminal) have no sibling to lose to.
        Assert.True(NavActiveState.IsActive("/Diagnostics/Vpn", "/Diagnostics"));
    }

    [Fact]
    public void AnyActive_OpensTheGroupFromAnyChild()
    {
        Assert.True(NavActiveState.AnyActive("/Diagnostics/capture", DiagGroup));
        Assert.False(NavActiveState.AnyActive("/Monitoring", DiagGroup));
    }
}
