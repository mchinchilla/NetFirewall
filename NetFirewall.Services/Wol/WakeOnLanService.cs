using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Logging;
using NetFirewall.Models;
using NetFirewall.Models.Diagnostics;
using NetFirewall.Models.Wol;
using NetFirewall.Services.Diagnostics;
using NetFirewall.Services.Firewall;

namespace NetFirewall.Services.Wol;

public sealed class WakeOnLanService : IWakeOnLanService
{
    private readonly IWolPacketSender _sender;
    private readonly IInterfaceHealthService _links;
    private readonly IFirewallService _fw;
    private readonly IDiagnosticInputValidator _validator;
    private readonly ILogger<WakeOnLanService> _logger;

    public WakeOnLanService(
        IWolPacketSender sender,
        IInterfaceHealthService links,
        IFirewallService fw,
        IDiagnosticInputValidator validator,
        ILogger<WakeOnLanService> logger)
    {
        _sender = sender;
        _links = links;
        _fw = fw;
        _validator = validator;
        _logger = logger;
    }

    public async Task<ServiceResponse<WolWakeResult>> WakeAsync(WolWakeRequest request, CancellationToken ct = default)
    {
        if (!MacAddressText.TryParse(request.Mac, out var mac, out var macText, out var error))
            return Fail(error);

        var port = request.Port ?? WolDefaults.Port;
        if (port is < 1 or > 65535) return Fail("Port must be 1-65535.");

        IPAddress? hint = null;
        if (!string.IsNullOrWhiteSpace(request.IpHint) && !TryIpv4(request.IpHint.Trim(), out hint))
            return Fail($"'{request.IpHint.Trim()}' is not an IPv4 address.");

        var live = await _links.GetAllAsync(ct);
        if (live.Count == 0)
            return Fail("No network links are visible here. Wake-on-LAN is sent by the daemon on the firewall itself.");

        HashSet<string> notLan;
        try
        {
            notLan = await NonLanNamesAsync(ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Wake-on-LAN: could not read the interface configuration");
            return Fail($"Could not read the interface configuration: {ex.Message}");
        }

        string iface;
        string source;
        if (!string.IsNullOrWhiteSpace(request.Interface))
        {
            var names = live.Where(l => l.Exists).Select(l => l.Name).ToHashSet(StringComparer.Ordinal);
            if (!_validator.TryInterfaceName(request.Interface, names, out iface, out error)) return Fail(error);
            if (notLan.Contains(iface))
                return Fail($"{iface} is not a LAN interface. A wake is only ever broadcast on the LAN side.");
            source = "requested";
        }
        else if (hint is not null)
        {
            var pick = PickBySubnet(live, hint, notLan);
            if (pick is null)
                return Fail($"No LAN interface on the firewall has a subnet containing {hint}. Pick the interface the device is plugged into.");
            iface = pick.Value.Iface;
            source = $"subnet {pick.Value.Cidr}";
        }
        else
        {
            return Fail("Pick the interface the device is plugged into.");
        }

        var link = live.First(l => l.Name == iface);
        if (string.Equals(link.OperState, "down", StringComparison.OrdinalIgnoreCase) || link.Carrier == false)
            return Fail($"{iface} is down (no carrier). The device cannot hear a wake on a dead link.");

        try
        {
            await _sender.SendAsync(MagicPacket.Build(mac), iface, IPAddress.Broadcast, port, WolDefaults.Copies, ct);
        }
        catch (Exception ex) when (ex is SocketException or PlatformNotSupportedException or UnauthorizedAccessException)
        {
            _logger.LogWarning(ex, "Wake-on-LAN to {Mac} on {Iface} failed", macText, iface);
            return Fail($"Could not send on {iface}: {ex.Message}");
        }

        _logger.LogInformation("Wake-on-LAN {Mac} on {Iface} ({Source}), udp/{Port} x{Copies}",
            macText, iface, source, port, WolDefaults.Copies);

        return ServiceResponse<WolWakeResult>.Ok(
            new WolWakeResult(macText, iface, source, IPAddress.Broadcast.ToString(), port, WolDefaults.Copies),
            $"Magic packet sent to {macText} on {iface}.");
    }

    /// <summary>Configured WAN and VPN links, plus loopback: never a place to broadcast a wake.</summary>
    private async Task<HashSet<string>> NonLanNamesAsync(CancellationToken ct)
    {
        var set = new HashSet<string>(StringComparer.Ordinal) { "lo" };
        foreach (var i in await _fw.GetInterfacesAsync(ct))
        {
            if (string.IsNullOrWhiteSpace(i.Name)) continue;
            if (string.Equals(i.Type, "WAN", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(i.Type, "VPN", StringComparison.OrdinalIgnoreCase))
                set.Add(i.Name);
        }
        return set;
    }

    // ───────────────────────── pure helpers ─────────────────────────

    /// <summary>
    /// The LAN link whose IPv4 subnet holds <paramref name="ip"/>; longest prefix wins
    /// (a VLAN /25 beats the /16 it sits in). Point-to-point /31 and /32 addresses
    /// are not segments anyone sleeps on and are skipped.
    /// </summary>
    internal static (string Iface, string Cidr)? PickBySubnet(
        IEnumerable<InterfaceHealth> links, IPAddress ip, IReadOnlySet<string> notLan)
    {
        (string Iface, string Cidr, int Prefix)? best = null;
        var target = ToUInt(ip);
        foreach (var link in links)
        {
            if (!link.Exists || notLan.Contains(link.Name)) continue;
            foreach (var address in link.Addresses)
            {
                if (!TryCidr(address, out var local, out var prefix) || prefix is < 1 or > 30) continue;
                var mask = uint.MaxValue << (32 - prefix);
                if ((ToUInt(local) & mask) != (target & mask)) continue;
                if (best is null || prefix > best.Value.Prefix)
                    best = (link.Name, $"{FromUInt(ToUInt(local) & mask)}/{prefix}", prefix);
            }
        }
        return best is null ? null : (best.Value.Iface, best.Value.Cidr);
    }

    /// <summary><c>a.b.c.d/n</c> as iproute2 prints it; IPv6 and bare addresses are not candidates.</summary>
    internal static bool TryCidr(string text, out IPAddress address, out int prefix)
    {
        address = IPAddress.None;
        prefix = 0;
        var slash = text.IndexOf('/');
        return slash > 0
               && TryIpv4(text[..slash], out address)
               && int.TryParse(text[(slash + 1)..], NumberStyles.None, CultureInfo.InvariantCulture, out prefix)
               && prefix <= 32;
    }

    /// <summary>
    /// A full dotted quad only: <see cref="IPAddress.TryParse(string, out IPAddress)"/>
    /// also takes "10.1" and "9", which are never what an operator meant.
    /// </summary>
    internal static bool TryIpv4(string text, out IPAddress address)
    {
        address = IPAddress.None;
        if (text.Count(c => c == '.') != 3) return false;
        if (!IPAddress.TryParse(text, out var parsed) || parsed.AddressFamily != AddressFamily.InterNetwork) return false;
        address = parsed;
        return true;
    }

    private static uint ToUInt(IPAddress ip) => BinaryPrimitives.ReadUInt32BigEndian(ip.GetAddressBytes());

    private static IPAddress FromUInt(uint value)
    {
        var bytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        return new IPAddress(bytes);
    }

    private static ServiceResponse<WolWakeResult> Fail(string? message) =>
        ServiceResponse<WolWakeResult>.Fail(message ?? "Invalid request.");
}
