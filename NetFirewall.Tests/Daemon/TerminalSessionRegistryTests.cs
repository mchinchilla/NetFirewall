using NetFirewall.Services.Processes;
using Xunit;

namespace NetFirewall.Tests.Daemon;

/// <summary>
/// The terminal registry is the heart of the web-terminal security model:
/// single-use attach tickets bound to (user, session) + a single concurrent
/// terminal. Pure in-memory logic, so fully testable without Linux/PTY.
/// </summary>
public sealed class TerminalSessionRegistryTests
{
    private static readonly Guid User = Guid.NewGuid();
    private static readonly Guid Session = Guid.NewGuid();

    [Fact]
    public void Ticket_redeems_once_then_is_dead()
    {
        var reg = new TerminalSessionRegistry();
        var ticket = reg.IssueTicket(User, Session);

        Assert.True(reg.TryRedeemTicket(ticket, out var u, out var s));
        Assert.Equal(User, u);
        Assert.Equal(Session, s);

        // Second redeem fails — single use (prevents replay).
        Assert.False(reg.TryRedeemTicket(ticket, out _, out _));
    }

    [Fact]
    public void Unknown_or_empty_ticket_is_rejected()
    {
        var reg = new TerminalSessionRegistry();
        Assert.False(reg.TryRedeemTicket("", out _, out _));
        Assert.False(reg.TryRedeemTicket("deadbeef", out _, out _));
    }

    [Fact]
    public void Issuing_a_new_ticket_invalidates_the_previous_one_for_the_same_session()
    {
        var reg = new TerminalSessionRegistry();
        var first = reg.IssueTicket(User, Session);
        var second = reg.IssueTicket(User, Session);

        Assert.NotEqual(first, second);
        // The first is now dead — only the latest open is redeemable.
        Assert.False(reg.TryRedeemTicket(first, out _, out _));
        Assert.True(reg.TryRedeemTicket(second, out _, out _));
    }

    [Fact]
    public void Tickets_for_different_sessions_are_independent()
    {
        var reg = new TerminalSessionRegistry();
        var otherSession = Guid.NewGuid();
        var a = reg.IssueTicket(User, Session);
        var b = reg.IssueTicket(User, otherSession);

        // Issuing b must NOT kill a (different session).
        Assert.True(reg.TryRedeemTicket(a, out _, out _));
        Assert.True(reg.TryRedeemTicket(b, out _, out _));
    }

    [Fact]
    public void Only_one_concurrent_terminal_slot()
    {
        var reg = new TerminalSessionRegistry();
        Assert.True(reg.TryAcquireSlot(User));
        Assert.False(reg.TryAcquireSlot(User));      // busy
        Assert.False(reg.TryAcquireSlot(Guid.NewGuid())); // busy for anyone

        reg.ReleaseSlot();
        Assert.True(reg.TryAcquireSlot(User));       // free again
    }
}
