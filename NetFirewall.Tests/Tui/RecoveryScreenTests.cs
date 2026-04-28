using NetFirewall.Models.Auth;
using NetFirewall.Tui.Screens;
using Xunit;

namespace NetFirewall.Tests.Tui;

/// <summary>
/// The interactive recovery flow can't be unit-tested without a TTY, but the
/// label-builder that decides what an operator sees in the picker IS pure and
/// worth pinning — a regression that drops "locked" or "no-totp" markers
/// would make break-glass operations harder right when the operator is
/// stressed (locked out at 2am).
/// </summary>
public class RecoveryScreenTests
{
    private static RecoveryUserSummary User(
        string username = "alice",
        string? displayName = null,
        string role = "admin",
        bool isActive = true,
        bool isLocked = false,
        bool hasTotp = true) =>
        new(Guid.NewGuid(), username, displayName, role, isActive, isLocked, hasTotp);

    [Fact]
    public void BuildUserChoiceLabel_HealthyUser_NoSuffix()
    {
        // Default state: nothing weird → no parenthesised marker block.
        var label = RecoveryScreen.BuildUserChoiceLabel(User("alice", role: "admin"));
        Assert.Contains("alice", label);
        Assert.Contains("admin", label);
        Assert.DoesNotContain("locked", label);
        Assert.DoesNotContain("inactive", label);
        Assert.DoesNotContain("no-totp", label);
    }

    [Fact]
    public void BuildUserChoiceLabel_LockedUser_HasLockedMarker()
    {
        var label = RecoveryScreen.BuildUserChoiceLabel(User("bob", isLocked: true));
        Assert.Contains("locked", label);
    }

    [Fact]
    public void BuildUserChoiceLabel_InactiveUser_HasInactiveMarker()
    {
        var label = RecoveryScreen.BuildUserChoiceLabel(User("carol", isActive: false));
        Assert.Contains("inactive", label);
    }

    [Fact]
    public void BuildUserChoiceLabel_UserWithoutTotp_HasNoTotpMarker()
    {
        // Important for recovery picker context: "no-totp" means disabling TOTP
        // would be a no-op. The marker tells the operator they probably want
        // password reset instead.
        var label = RecoveryScreen.BuildUserChoiceLabel(User("dave", hasTotp: false));
        Assert.Contains("no-totp", label);
    }

    [Fact]
    public void BuildUserChoiceLabel_AllProblems_AllMarkersPresent()
    {
        // Worst-case: locked + inactive + no-totp. All three should surface so
        // the operator sees the full picture before picking an action.
        var label = RecoveryScreen.BuildUserChoiceLabel(
            User("erin", isActive: false, isLocked: true, hasTotp: false));
        Assert.Contains("locked", label);
        Assert.Contains("inactive", label);
        Assert.Contains("no-totp", label);
    }
}
