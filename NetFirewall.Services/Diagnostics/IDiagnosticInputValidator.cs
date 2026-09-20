namespace NetFirewall.Services.Diagnostics;

/// <summary>
/// Allow-list validation for everything a diagnostics request may carry into a
/// process argument. Runs in the Web (before proxying) AND in the daemon (before
/// spawning) — neither trusts the other. Pure: no IO, no DB.
/// </summary>
public interface IDiagnosticInputValidator
{
    /// <summary>IPv4/IPv6 literal (no zone id) or an RFC-1123 hostname. Never starts with '-'.</summary>
    bool TryHost(string? input, out string normalized, out string? error);

    /// <summary>IP literal or CIDR (<c>a.b.c.d/n</c>, <c>x::/n</c>).</summary>
    bool TryCidrOrIp(string? input, out string normalized, out string? error);

    /// <summary>Interface name: kernel charset/length AND member of <paramref name="allowed"/>.</summary>
    bool TryInterfaceName(string? input, IReadOnlySet<string> allowed, out string normalized, out string? error);

    /// <summary><c>0x…</c> or decimal in 1..0xFFFFFFFF. Empty/null → <c>0</c> (no mark) and true.</summary>
    bool TryFwmark(string? input, out long mark, out string? error);

    /// <summary>tcp | udp | icmp (case-insensitive). Empty/null → "" and true.</summary>
    bool TryProto(string? input, out string normalized, out string? error);

    bool TryPort(int? input, out int port, out string? error);

    int Clamp(int value, int min, int max);

    /// <summary>
    /// Character-level allow-list for a tcpdump/BPF filter. Deliberately narrow:
    /// it admits the pcap-filter language (hosts, ports, protocols, and/or/not,
    /// parentheses, comparisons) and nothing that could be read as shell or as a
    /// tcpdump option. The daemon additionally compiles it with <c>tcpdump -d</c>
    /// before capturing.
    /// </summary>
    bool TryBpfFilter(string? input, out string normalized, out string? error);

    /// <summary>Remove <c>PrivateKey</c>/<c>PresharedKey</c> lines from a pasted wg-quick config.</summary>
    string RedactWgConfig(string text);
}
