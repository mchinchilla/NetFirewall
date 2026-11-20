using System.Net;
using System.Net.NetworkInformation;
using NetFirewall.Models.Dhcp;
using NetFirewall.Services.Dhcp;
using NetFirewall.Web.Models.Dhcp;

namespace NetFirewall.Web.Services;

/// <summary>
/// Composes <see cref="IDhcpAdminService"/> reads (lease by MAC, the reservation for that MAC,
/// the subnet that contains the leased IP). Three sequential queries, only when a row is expanded.
/// </summary>
public sealed class DhcpLeaseDetailService(IDhcpAdminService admin) : IDhcpLeaseDetailService
{
    public async Task<LeaseDetailViewModel?> GetAsync(string mac, CancellationToken ct = default)
    {
        if (!TryNormalizeMac(mac, out var normalized)) return null;

        var lease = await admin.GetLeaseByMacAsync(normalized, ct);
        if (lease is null) return null;

        var reservations = await admin.GetReservationsAsync(ct: ct);
        var reservation = reservations.FirstOrDefault(r => r.MacAddress.Equals(lease.MacAddress));

        var subnets = await admin.GetSubnetsAsync(ct);
        var subnet = subnets.FirstOrDefault(s => IPNetwork.TryParse(s.Network, out var net) && net.Contains(lease.IpAddress));

        return new LeaseDetailViewModel { Lease = lease, Mac = normalized, Reservation = reservation, Subnet = subnet };
    }

    /// <summary>Accepts aa:bb:…, aa-bb-… or aabb…; returns the lower-case colon form.</summary>
    private static bool TryNormalizeMac(string? text, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(text) || text.Length > 17) return false;
        var hex = text.Replace(":", "").Replace("-", "");
        if (hex.Length != 12 || !hex.All(Uri.IsHexDigit)) return false;
        normalized = string.Join(':', Enumerable.Range(0, 6).Select(i => hex.Substring(i * 2, 2))).ToLowerInvariant();
        return PhysicalAddress.TryParse(hex, out _);
    }
}
