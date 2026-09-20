using System.Text.Json;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.Diagnostics;

public sealed class InterfaceHealthService : IInterfaceHealthService
{
    private const string NetClass = "/sys/class/net";
    private static readonly TimeSpan Budget = TimeSpan.FromSeconds(5);

    private readonly IProcessRunner _runner;
    private readonly DiagnosticsOptions _opts;

    public InterfaceHealthService(IProcessRunner runner, IOptions<DiagnosticsOptions> opts)
    {
        _runner = runner;
        _opts = opts.Value;
    }

    public Task<IReadOnlySet<string>> ListNamesAsync(CancellationToken ct = default)
    {
        IReadOnlySet<string> names = OperatingSystem.IsLinux() && Directory.Exists(NetClass)
            ? Directory.EnumerateDirectories(NetClass).Select(Path.GetFileName).OfType<string>().ToHashSet(StringComparer.Ordinal)
            : new HashSet<string>(StringComparer.Ordinal);
        return Task.FromResult(names);
    }

    public async Task<IReadOnlyList<InterfaceHealth>> GetAllAsync(CancellationToken ct = default)
    {
        if (!OperatingSystem.IsLinux()) return Array.Empty<InterfaceHealth>();
        var names = await ListNamesAsync(ct);
        var addrs = await AddressesAsync(null, ct);
        var list = new List<InterfaceHealth>();
        foreach (var name in names.OrderBy(n => n, StringComparer.Ordinal))
            list.Add(await ReadOneAsync(name, addrs.GetValueOrDefault(name) ?? Array.Empty<string>(), ct));
        return list;
    }

    public async Task<InterfaceHealth?> GetAsync(string iface, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsLinux()) return null;
        if (!Directory.Exists(Path.Combine(NetClass, iface)))
            return new InterfaceHealth(iface, false, null, null, null, Array.Empty<string>(), null, null, 0, 0, 0, 0, 0, 0);
        var addrs = await AddressesAsync(iface, ct);
        return await ReadOneAsync(iface, addrs.GetValueOrDefault(iface) ?? Array.Empty<string>(), ct);
    }

    public async Task<IReadOnlyList<NeighborEntry>> NeighborsAsync(string? iface, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsLinux()) return Array.Empty<NeighborEntry>();
        var args = new List<string> { "-j", "neigh", "show" };
        if (!string.IsNullOrEmpty(iface)) { args.Add("dev"); args.Add(iface); }
        var run = await _runner.RunAsync(_opts.IpPath, args, Budget, ct);
        return run.Success ? ParseNeighbors(run.Output) : Array.Empty<NeighborEntry>();
    }

    // ───────────────────────── sysfs ─────────────────────────

    private static async Task<InterfaceHealth> ReadOneAsync(string name, IReadOnlyList<string> addresses, CancellationToken ct)
    {
        var dir = Path.Combine(NetClass, name);
        var carrier = await ReadAsync(dir, "carrier", ct);
        var speed = await ReadAsync(dir, "speed", ct);
        return new InterfaceHealth(
            name,
            Exists: true,
            OperState: await ReadAsync(dir, "operstate", ct),
            Carrier: carrier is null ? null : carrier == "1",
            Mtu: int.TryParse(await ReadAsync(dir, "mtu", ct), out var mtu) ? mtu : null,
            Addresses: addresses,
            Speed: speed is null || speed.StartsWith('-') ? null : speed + " Mb/s",
            Duplex: await ReadAsync(dir, "duplex", ct),
            RxBytes:   await StatAsync(dir, "rx_bytes", ct),
            TxBytes:   await StatAsync(dir, "tx_bytes", ct),
            RxErrors:  await StatAsync(dir, "rx_errors", ct),
            TxErrors:  await StatAsync(dir, "tx_errors", ct),
            RxDropped: await StatAsync(dir, "rx_dropped", ct),
            TxDropped: await StatAsync(dir, "tx_dropped", ct));
    }

    /// <summary>sysfs attributes throw EINVAL/ENOTSUP on virtual links (speed on wg0, carrier on a down link) — that is "unknown", not an error.</summary>
    private static async Task<string?> ReadAsync(string dir, string attr, CancellationToken ct)
    {
        try { return (await File.ReadAllTextAsync(Path.Combine(dir, attr), ct)).Trim(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    private static async Task<long> StatAsync(string dir, string stat, CancellationToken ct) =>
        long.TryParse(await ReadAsync(Path.Combine(dir, "statistics"), stat, ct), out var v) ? v : 0;

    // ───────────────────────── iproute2 JSON ─────────────────────────

    private async Task<Dictionary<string, IReadOnlyList<string>>> AddressesAsync(string? iface, CancellationToken ct)
    {
        var args = new List<string> { "-j", "addr", "show" };
        if (!string.IsNullOrEmpty(iface)) { args.Add("dev"); args.Add(iface); }
        var run = await _runner.RunAsync(_opts.IpPath, args, Budget, ct);
        return run.Success ? ParseAddresses(run.Output) : new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
    }

    internal static Dictionary<string, IReadOnlyList<string>> ParseAddresses(string json)
    {
        var map = new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal);
        try
        {
            using var doc = JsonDocument.Parse(json);
            foreach (var link in doc.RootElement.EnumerateArray())
            {
                var name = Str(link, "ifname");
                if (name is null) continue;
                var addrs = new List<string>();
                if (link.TryGetProperty("addr_info", out var infos) && infos.ValueKind == JsonValueKind.Array)
                    foreach (var a in infos.EnumerateArray())
                    {
                        var local = Str(a, "local");
                        if (local is null) continue;
                        var plen = a.TryGetProperty("prefixlen", out var p) && p.ValueKind == JsonValueKind.Number ? p.GetInt32() : (int?)null;
                        addrs.Add(plen is null ? local : $"{local}/{plen}");
                    }
                map[name] = addrs;
            }
        }
        catch (JsonException) { /* unparseable → empty */ }
        return map;
    }

    internal static IReadOnlyList<NeighborEntry> ParseNeighbors(string json)
    {
        var list = new List<NeighborEntry>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            foreach (var n in doc.RootElement.EnumerateArray())
            {
                var ip = Str(n, "dst");
                var dev = Str(n, "dev");
                if (ip is null || dev is null) continue;
                var state = n.TryGetProperty("state", out var st) && st.ValueKind == JsonValueKind.Array
                    ? string.Join(",", st.EnumerateArray().Select(s => s.GetString()))
                    : "?";
                list.Add(new NeighborEntry(ip, Str(n, "lladdr"), dev, state));
            }
        }
        catch (JsonException) { /* unparseable → empty */ }
        return list;
    }

    private static string? Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
