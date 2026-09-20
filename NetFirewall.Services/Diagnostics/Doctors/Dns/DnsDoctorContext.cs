using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Models.Firewall;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Monitoring;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.Diagnostics.Doctors.Dns;

/// <summary>
/// State for the DNS doctor, plus the resolver probe itself.
///
/// The probe speaks DNS over UDP directly instead of shelling out to <c>dig</c>:
/// dnsutils is not a dependency of this appliance, and a 40-line query beats
/// adding a package just to time a lookup.
/// </summary>
public sealed class DnsDoctorContext
{
    private readonly Lazy<Task<IReadOnlyList<FwInterface>>> _interfaces;
    private readonly Lazy<Task<IReadOnlyList<ServiceHealth>>> _units;
    private readonly Lazy<Task<IReadOnlyList<InterfaceHealth>>> _links;
    private readonly Lazy<Task<string>> _listeners;
    private readonly Lazy<Task<string>> _ruleset;

    public string ProbeName { get; }

    internal DnsDoctorContext(
        string probeName,
        IFirewallService fw,
        ISystemServiceHealthService units,
        IInterfaceHealthService links,
        INftApplyService nft,
        IProcessRunner runner,
        CancellationToken ct)
    {
        ProbeName = probeName;
        _interfaces = new(() => fw.GetInterfacesAsync(ct));
        _units      = new(() => units.GetAllAsync(ct));
        _links      = new(() => links.GetAllAsync(ct));
        _ruleset    = new(() => nft.GetCurrentRulesetAsync(ct));
        _listeners  = new(async () =>
        {
            if (!OperatingSystem.IsLinux()) return string.Empty;
            // Both transports: a resolver that lost its TCP listener fails big answers only.
            var res = await runner.RunAsync("ss", ["-lntup"], TimeSpan.FromSeconds(5), ct);
            return res.Output ?? string.Empty;
        });
    }

    public Task<IReadOnlyList<FwInterface>> InterfacesAsync() => _interfaces.Value;
    public Task<IReadOnlyList<ServiceHealth>> UnitsAsync() => _units.Value;
    public Task<IReadOnlyList<InterfaceHealth>> LinksAsync() => _links.Value;
    public Task<string> ListenersAsync() => _listeners.Value;
    public Task<string> LiveRulesetAsync() => _ruleset.Value;

    public async Task<ServiceHealth?> ResolverUnitAsync() =>
        (await UnitsAsync()).FirstOrDefault(u =>
            u.UnitName.Contains("unbound", StringComparison.OrdinalIgnoreCase) ||
            u.UnitName.Contains("dnsmasq", StringComparison.OrdinalIgnoreCase) ||
            u.UnitName.Contains("named", StringComparison.OrdinalIgnoreCase) ||
            u.UnitName.Contains("bind9", StringComparison.OrdinalIgnoreCase));

    /// <summary>Ask a resolver for an A record over UDP and time it. Pure sockets, no external binary.</summary>
    public static async Task<DnsProbe> QueryAsync(IPAddress server, string name, int timeoutMs = 2000, CancellationToken ct = default)
    {
        var query = BuildQuery(name, out var id);
        using var udp = new UdpClient(server.AddressFamily);
        var sw = Stopwatch.StartNew();
        try
        {
            udp.Client.ReceiveTimeout = timeoutMs;
            await udp.SendAsync(query, new IPEndPoint(server, 53), ct);

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(timeoutMs);
            var reply = await udp.ReceiveAsync(cts.Token);
            sw.Stop();

            var (rcode, answers) = ParseReply(reply.Buffer, id);
            return new DnsProbe(true, rcode, answers, sw.Elapsed.TotalMilliseconds, null);
        }
        catch (OperationCanceledException)
        {
            return new DnsProbe(false, null, 0, sw.Elapsed.TotalMilliseconds, $"No answer within {timeoutMs} ms.");
        }
        catch (Exception ex)
        {
            return new DnsProbe(false, null, 0, sw.Elapsed.TotalMilliseconds, ex.Message);
        }
    }

    /// <summary>Minimal A-record query: header + QNAME + QTYPE/QCLASS, recursion desired.</summary>
    internal static byte[] BuildQuery(string name, out ushort id)
    {
        id = (ushort)Random.Shared.Next(1, ushort.MaxValue);
        var body = new List<byte>
        {
            (byte)(id >> 8), (byte)(id & 0xFF),
            0x01, 0x00,             // flags: standard query, recursion desired
            0x00, 0x01,             // QDCOUNT = 1
            0x00, 0x00,             // ANCOUNT
            0x00, 0x00,             // NSCOUNT
            0x00, 0x00,             // ARCOUNT
        };
        foreach (var label in name.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var bytes = System.Text.Encoding.ASCII.GetBytes(label);
            if (bytes.Length > 63) throw new ArgumentException("DNS label too long.", nameof(name));
            body.Add((byte)bytes.Length);
            body.AddRange(bytes);
        }
        body.Add(0x00);             // root label
        body.AddRange([0x00, 0x01]); // QTYPE A
        body.AddRange([0x00, 0x01]); // QCLASS IN
        return body.ToArray();
    }

    /// <summary>Returns the RCODE name and the answer count; we do not need the records themselves.</summary>
    internal static (string Rcode, int Answers) ParseReply(byte[] reply, ushort expectedId)
    {
        if (reply.Length < 12) return ("MALFORMED", 0);
        var id = (ushort)((reply[0] << 8) | reply[1]);
        if (id != expectedId) return ("MISMATCH", 0);

        var rcode = reply[3] & 0x0F;
        var answers = (reply[6] << 8) | reply[7];
        var name = rcode switch
        {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            _ => $"RCODE{rcode}",
        };
        return (name, answers);
    }
}

public sealed record DnsProbe(bool Answered, string? Rcode, int Answers, double ElapsedMs, string? Error);

public interface IDnsDoctorContextFactory
{
    DnsDoctorContext Create(string probeName, CancellationToken ct);
}

public sealed class DnsDoctorContextFactory : IDnsDoctorContextFactory
{
    private readonly IFirewallService _fw;
    private readonly ISystemServiceHealthService _units;
    private readonly IInterfaceHealthService _links;
    private readonly INftApplyService _nft;
    private readonly IProcessRunner _runner;

    public DnsDoctorContextFactory(IFirewallService fw, ISystemServiceHealthService units, IInterfaceHealthService links, INftApplyService nft, IProcessRunner runner)
    {
        _fw = fw; _units = units; _links = links; _nft = nft; _runner = runner;
    }

    public DnsDoctorContext Create(string probeName, CancellationToken ct) =>
        new(probeName, _fw, _units, _links, _nft, _runner, ct);
}

public interface IDnsDoctorCheck : IDoctorCheck<DnsDoctorContext> { }
public abstract class DnsDoctorCheckBase : DoctorCheckBase<DnsDoctorContext>, IDnsDoctorCheck { }

public static class DnsRemedies
{
    public static DiagRemedy Forwarder(string? hint = null) => new("DNS forwarder", "/Network/Dns", hint);
    public static DiagRemedy FilterRules(string? hint = null) => new("Filter rules", "/Firewall/FilterRules", hint);
    public static DiagRemedy Service(string? hint = null) => new("Service health", "/Monitoring", hint);
}
