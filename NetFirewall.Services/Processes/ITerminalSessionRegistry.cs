using System.Collections.Concurrent;

namespace NetFirewall.Services.Processes;

/// <summary>
/// Mints and redeems one-time attach tickets for the web terminal, and enforces a
/// single concurrent live terminal across the whole daemon. The open→attach split
/// is the CSRF/replay defense: <c>POST /v1/terminal/open</c> (TOTP-gated) mints a
/// short-lived single-use ticket bound to the caller's (user, session); the WS
/// <c>GET /v1/terminal/attach</c> redeems it. A WS upgrade can't carry an
/// antiforgery token, so the unguessable ticket is what authorizes the attach.
///
/// Pure in-memory logic (no platform code) — lives in NetFirewall.Services next to
/// <see cref="IPtyService"/> so it's testable cross-platform without the daemon
/// assembly's linux marking.
/// </summary>
public interface ITerminalSessionRegistry
{
    /// <summary>Mint a single-use attach ticket bound to (userId, sessionId).
    /// Returns the opaque ticket string. Old unredeemed tickets for the same
    /// session are invalidated.</summary>
    string IssueTicket(Guid userId, Guid sessionId);

    /// <summary>Atomically redeem a ticket. Returns true (with the bound identity)
    /// only if the ticket exists, is unexpired, and is consumed exactly once.</summary>
    bool TryRedeemTicket(string ticket, out Guid userId, out Guid sessionId);

    /// <summary>Try to claim the single live-terminal slot. Returns false if one is
    /// already active. Caller MUST call <see cref="ReleaseSlot"/> when the terminal
    /// ends.</summary>
    bool TryAcquireSlot(Guid userId);

    /// <summary>Release the live-terminal slot.</summary>
    void ReleaseSlot();
}

public sealed class TerminalSessionRegistry : ITerminalSessionRegistry
{
    // Tickets are short-lived (30s) and single-use. ip.guide-style: small map,
    // cleaned lazily on issue/redeem.
    private static readonly TimeSpan TicketTtl = TimeSpan.FromSeconds(30);

    private sealed record Ticket(Guid UserId, Guid SessionId, DateTimeOffset ExpiresAt);

    private readonly ConcurrentDictionary<string, Ticket> _tickets = new();
    private int _slotTaken; // 0 = free, 1 = taken (Interlocked)

    public string IssueTicket(Guid userId, Guid sessionId)
    {
        Sweep();
        // Invalidate any prior tickets for this session so a leaked older ticket
        // can't be redeemed after a re-open.
        foreach (var kv in _tickets)
            if (kv.Value.SessionId == sessionId) _tickets.TryRemove(kv.Key, out _);

        var ticket = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        _tickets[ticket] = new Ticket(userId, sessionId, DateTimeOffset.UtcNow + TicketTtl);
        return ticket;
    }

    public bool TryRedeemTicket(string ticket, out Guid userId, out Guid sessionId)
    {
        userId = default;
        sessionId = default;
        if (string.IsNullOrEmpty(ticket)) return false;
        if (!_tickets.TryRemove(ticket, out var t)) return false; // single-use: removed on redeem
        if (t.ExpiresAt < DateTimeOffset.UtcNow) return false;     // expired
        userId = t.UserId;
        sessionId = t.SessionId;
        return true;
    }

    public bool TryAcquireSlot(Guid userId) => Interlocked.CompareExchange(ref _slotTaken, 1, 0) == 0;

    public void ReleaseSlot() => Interlocked.Exchange(ref _slotTaken, 0);

    private void Sweep()
    {
        var now = DateTimeOffset.UtcNow;
        foreach (var kv in _tickets)
            if (kv.Value.ExpiresAt < now) _tickets.TryRemove(kv.Key, out _);
    }
}
