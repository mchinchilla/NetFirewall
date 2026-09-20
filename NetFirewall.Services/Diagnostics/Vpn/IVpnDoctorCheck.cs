using NetFirewall.Models.Diagnostics;

namespace NetFirewall.Services.Diagnostics.Vpn;

/// <summary>
/// One rule of the VPN doctor. Checks are registered as <c>IEnumerable&lt;IVpnDoctorCheck&gt;</c>
/// in registration order, run concurrently against a shared <see cref="VpnDoctorContext"/>
/// (every command/query is executed once and memoised), and must be fail-soft:
/// anything they cannot determine is a <see cref="DiagCheckStatus.Skip"/>, never an exception.
/// A check may emit several rows (one per peer, for example).
/// </summary>
public interface IVpnDoctorCheck : Doctors.IDoctorCheck<VpnDoctorContext>
{
}

/// <summary>Single-row convenience base; the fail-soft wrapper lives in the shared <see cref="Doctors.DoctorCheckBase{T}"/>.</summary>
public abstract class VpnDoctorCheckBase : Doctors.DoctorCheckBase<VpnDoctorContext>, IVpnDoctorCheck
{
}

/// <summary>Remedy deep-links shared by the checks. Paths, not Url.Action — the daemon has no routing table.</summary>
public static class VpnRemedies
{
    public static DiagRemedy ApplyVpn(string? hint = null) => new("Apply VPN", "/Vpn/WireGuard", hint ?? "Writes wg0.conf, brings the link up (cold restart when the address/MTU changed) and re-installs the tunnel's routes.");
    public static DiagRemedy PolicyRouting(string? hint = null) => new("Re-apply policy routing", "/Firewall/Apply", hint ?? "Firewall → Apply → Policy routing → Execute.");
    public static DiagRemedy ApplyFirewall(string? hint = null) => new("Apply firewall rules", "/Firewall/Apply", hint);
    public static DiagRemedy ServerForm(string? hint = null) => new("Edit interface", "/Vpn/WireGuard", hint);
    public static DiagRemedy PeerForm(Guid peerId, string? hint = null) => new("Edit peer", $"/Vpn/WireGuard/Peers/edit/{peerId}", hint);
    public static DiagRemedy MangleRules(string? hint = null) => new("Mangle rules", "/Firewall/MangleRules", hint);
    public static DiagRemedy FilterRules(string? hint = null) => new("Filter rules", "/Firewall/FilterRules", hint);
    public static DiagRemedy DropLog(string? hint = null) => new("Open drop log", "/Diagnostics/drop-log", hint);
    public static DiagRemedy Compare(string? hint = null) => new("Compare with issued config", "/Diagnostics/Vpn#compare", hint);
}
