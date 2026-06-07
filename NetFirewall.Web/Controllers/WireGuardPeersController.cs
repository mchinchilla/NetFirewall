using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Models.Auth;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Settings;
using NetFirewall.Services.Vpn;
using NetFirewall.Services.Daemon;
using NetFirewall.Web.Helpers;
using NetFirewall.Web.Models.Vpn;

namespace NetFirewall.Web.Controllers;

[Authorize(Roles = $"{UserRoles.Admin},{UserRoles.Operator}")]
[Route("/Vpn/WireGuard/Peers")]
public sealed class WireGuardPeersController : Controller
{
    private readonly IWireGuardService _wg;
    private readonly IWireGuardConfigService _configGen;
    private readonly IVpnRoutingService _vpnRouting;
    private readonly NetFirewall.Services.Firewall.IFirewallService _fw;
    private readonly IDaemonClient _daemon;
    private readonly IAppSettingsService _settings;
    private readonly ILogger<WireGuardPeersController> _logger;

    public WireGuardPeersController(
        IWireGuardService wg,
        IWireGuardConfigService configGen,
        IVpnRoutingService vpnRouting,
        NetFirewall.Services.Firewall.IFirewallService fw,
        IDaemonClient daemon,
        IAppSettingsService settings,
        ILogger<WireGuardPeersController> logger)
    {
        _wg = wg;
        _configGen = configGen;
        _vpnRouting = vpnRouting;
        _fw = fw;
        _daemon = daemon;
        _settings = settings;
        _logger = logger;
    }

    [HttpGet("table")]
    public async Task<IActionResult> Table(CancellationToken ct)
    {
        var server = await _wg.GetServerAsync(ct);
        if (server is null) return PartialView("_PeersTable", Array.Empty<WgPeer>());
        // Stash mode so the table can relabel itself (client mode = "remote server",
        // server mode = "peers") and show the per-peer access column where relevant.
        ViewData["wg.mode"] = server.Mode;
        var peers = await _wg.GetPeersAsync(server.Id, ct);
        return PartialView("_PeersTable", peers);
    }

    [HttpGet("edit/{id:guid?}")]
    public async Task<IActionResult> Edit(Guid? id, CancellationToken ct)
    {
        var server = await _wg.GetServerAsync(ct);
        if (server is null) return NotFound();

        if (id is null)
        {
            // Suggest the next .X address inside the server's subnet.
            var suggested = SuggestNextPeerCidr(server, await _wg.GetPeersAsync(server.Id, ct));
            return PartialView("_PeerForm", new WgPeerFormViewModel
            {
                ServerId = server.Id,
                AllowedIpsRaw = suggested,
                PersistentKeepalive = 25,
            });
        }

        var peer = await _wg.GetPeerByIdAsync(id.Value, ct);
        return peer is null ? NotFound() : PartialView("_PeerForm", FromEntity(peer));
    }

    [HttpPost("save"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Save(WgPeerFormViewModel form, CancellationToken ct)
    {
        if (!ModelState.IsValid)
            return this.ToHtmxResponse(ServiceResponse<object>.Fail("Form validation failed."));

        try
        {
            var server = await _wg.GetServerAsync(ct);
            if (server is null) return this.ToHtmxResponse(ServiceResponse<object>.Fail("No WireGuard server configured."));

            var allowedIps = form.AllowedIpsRaw
                .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToArray();
            if (allowedIps.Length == 0)
                return this.ToHtmxResponse(ServiceResponse<object>.Fail("Allowed IPs cannot be empty."));

            var isNew = !form.Id.HasValue;
            string? clientPrivateKey = null;
            WgPeer entity;

            if (isNew)
            {
                // Generate the peer's keypair on the daemon. Server stores PUBLIC,
                // we hand the private back to the operator ONCE in the response.
                var keys = await _daemon.GenerateWireGuardKeyPairAsync(ct);
                if (!keys.Success || keys.Data is null)
                    return this.ToHtmxResponse(ServiceResponse<object>.Fail($"Key gen failed: {keys.Message}"));
                clientPrivateKey = keys.Data.PrivateKey;

                entity = new WgPeer
                {
                    ServerId = server.Id,
                    Name = form.Name,
                    PublicKey = keys.Data.PublicKey,
                    PresharedKey = string.IsNullOrEmpty(form.PresharedKey) ? null : form.PresharedKey,
                    AllowedIps = allowedIps,
                    PersistentKeepalive = form.PersistentKeepalive is > 0 ? form.PersistentKeepalive : null,
                    Endpoint = string.IsNullOrWhiteSpace(form.Endpoint) ? null : form.Endpoint.Trim(),
                    RouteMode = string.IsNullOrWhiteSpace(form.RouteMode) ? "full" : form.RouteMode,
                    AllowedSubnets = ParseList(form.AllowedSubnetsRaw),
                    Description = form.Description,
                    Enabled = form.Enabled
                };
                entity = await _wg.CreatePeerAsync(entity, ct);
            }
            else
            {
                entity = await _wg.GetPeerByIdAsync(form.Id!.Value, ct)
                    ?? throw new InvalidOperationException("Peer not found.");
                entity.Name = form.Name;
                entity.PresharedKey = string.IsNullOrEmpty(form.PresharedKey) ? null : form.PresharedKey;
                entity.AllowedIps = allowedIps;
                entity.PersistentKeepalive = form.PersistentKeepalive is > 0 ? form.PersistentKeepalive : null;
                entity.Endpoint = string.IsNullOrWhiteSpace(form.Endpoint) ? null : form.Endpoint.Trim();
                entity.RouteMode = string.IsNullOrWhiteSpace(form.RouteMode) ? "full" : form.RouteMode;
                entity.AllowedSubnets = ParseList(form.AllowedSubnetsRaw);
                entity.Description = form.Description;
                entity.Enabled = form.Enabled;
                await _wg.UpdatePeerAsync(entity, ct);
            }

            // Phase D: ensure NAT/forward for this peer's intent (server mode only;
            // the service no-ops in client mode). Best-effort — non-fatal.
            if (server.Mode.Equals("server", StringComparison.OrdinalIgnoreCase))
            {
                try { await _vpnRouting.EnsurePeerForwardingAsync(server, entity, ct); }
                catch (Exception ex) { _logger.LogWarning(ex, "Peer forwarding ensure failed (non-fatal)"); }
            }

            Response.Headers["HX-Trigger"] = "refreshWireGuardPeers";

            // For NEW peers we render the client config view in-drawer so the
            // operator can copy/QR before navigating away. For updates, just toast.
            if (isNew && clientPrivateKey is not null)
            {
                var endpoint = await _settings.GetStringAsync("vpn.public_endpoint", ct);
                if (string.IsNullOrWhiteSpace(endpoint)) endpoint = "<set vpn.public_endpoint in Settings>";
                var dns = await _settings.GetStringAsync("vpn.client_dns", ct);

                var clientCidr = entity.AllowedIps.FirstOrDefault() ?? "10.10.0.2/32";
                // Client-side AllowedIPs (what the CLIENT routes into the tunnel) is
                // driven by intent — NOT the server-side peer AllowedIPs. full = all
                // traffic; split/restricted/site = only the LAN/target subnets.
                var clientAllowedIps = await ComputeClientAllowedIpsAsync(entity, ct);
                var clientConfig = _configGen.GenerateClientConfig(
                    server, entity, clientPrivateKey, endpoint, clientCidr,
                    clientAllowedIps,
                    string.IsNullOrWhiteSpace(dns) ? null : dns);

                return PartialView("_PeerCreated", new WgPeerCreatedViewModel
                {
                    PeerId = entity.Id,
                    PeerName = entity.Name,
                    ClientConfig = clientConfig
                });
            }

            var envelope = ServiceResponse<object>.Ok(new { entity.Id }, $"Peer '{entity.Name}' saved.");
            this.AttachToastTrigger(envelope);
            return Json(envelope);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "WireGuard peer save failed");
            return this.ToHtmxResponse(ServiceResponse<object>.Fail($"Save failed: {ex.Message}"));
        }
    }

    [HttpPost("delete/{id:guid}"), ValidateAntiForgeryToken]
    public async Task<IActionResult> Delete(Guid id, CancellationToken ct)
    {
        // Remove this peer's [vpn-auto] NAT/forward rows before deleting it.
        var server = await _wg.GetServerAsync(ct);
        var peer = await _wg.GetPeerByIdAsync(id, ct);
        if (server is not null && peer is not null)
        {
            try { await _vpnRouting.RemovePeerForwardingAsync(server, peer, ct); }
            catch (Exception ex) { _logger.LogWarning(ex, "Peer forwarding cleanup failed (non-fatal)"); }
        }

        var ok = await _wg.DeletePeerAsync(id, ct);
        Response.Headers["HX-Trigger"] = "refreshWireGuardPeers";
        return this.ToHtmxResponse(ok
            ? ServiceResponse<object>.Ok(new { }, "Peer deleted.")
            : ServiceResponse<object>.Fail("Peer not found."));
    }

    // ----- helpers -----

    private static string[] ParseList(string? raw) =>
        string.IsNullOrWhiteSpace(raw)
            ? Array.Empty<string>()
            : raw.Split(new[] { ',', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    /// <summary>Client-side AllowedIPs from the peer's intent: full → 0.0.0.0/0;
    /// split → the firewall's LAN subnets; restricted/site → the peer's AllowedSubnets
    /// (fallback to LAN subnets if none given).</summary>
    private async Task<IReadOnlyList<string>> ComputeClientAllowedIpsAsync(WgPeer peer, CancellationToken ct)
    {
        var mode = (peer.RouteMode ?? "full").ToLowerInvariant();
        if (mode == "full") return new[] { "0.0.0.0/0" };

        if (mode is "restricted" or "site" && peer.AllowedSubnets is { Length: > 0 })
            return peer.AllowedSubnets;

        // split (or restricted/site with no explicit subnets) → the LAN subnets.
        var lanSubnets = (await _fw.GetInterfacesAsync(ct))
            .Where(i => i.Type == "LAN" && i.Enabled && i.IpAddress is not null && i.SubnetMask is not null)
            .Select(i => ToCidr(i.IpAddress!, i.SubnetMask!))
            .Where(c => c is not null)
            .Select(c => c!)
            .ToArray();
        return lanSubnets.Length > 0 ? lanSubnets : new[] { "0.0.0.0/0" };
    }

    private static string? ToCidr(System.Net.IPAddress ip, System.Net.IPAddress mask)
    {
        var maskBytes = mask.GetAddressBytes();
        int bits = maskBytes.Sum(b => System.Numerics.BitOperations.PopCount((uint)b));
        // Network address = ip & mask.
        var ipBytes = ip.GetAddressBytes();
        if (ipBytes.Length != maskBytes.Length) return null;
        for (int i = 0; i < ipBytes.Length; i++) ipBytes[i] &= maskBytes[i];
        return $"{new System.Net.IPAddress(ipBytes)}/{bits}";
    }

    /// <summary>
    /// Server is e.g. 10.10.0.1/24. Pick the lowest unused .2..254 octet
    /// inside that /24 — good enough for the most common case. For more
    /// exotic subnets (non-/24, IPv6) we just suggest .2/32 and let the
    /// operator override.
    /// </summary>
    private static string SuggestNextPeerCidr(WgServer server, IReadOnlyList<WgPeer> peers)
    {
        try
        {
            var slash = server.AddressCidr.IndexOf('/');
            if (slash <= 0) return "10.10.0.2/32";
            var ipPart = server.AddressCidr[..slash];
            var octets = ipPart.Split('.');
            if (octets.Length != 4) return "10.10.0.2/32";

            var prefix = $"{octets[0]}.{octets[1]}.{octets[2]}.";
            var used = new HashSet<int>();
            foreach (var p in peers)
            foreach (var ip in p.AllowedIps)
            {
                var ipOnly = ip.Contains('/') ? ip[..ip.IndexOf('/')] : ip;
                if (ipOnly.StartsWith(prefix) && byte.TryParse(ipOnly.AsSpan(prefix.Length), out var n))
                    used.Add(n);
            }
            // server's own .X is taken too
            if (byte.TryParse(octets[3], out var serverOctet)) used.Add(serverOctet);

            for (var i = 2; i < 255; i++)
                if (!used.Contains(i))
                    return $"{prefix}{i}/32";
        }
        catch { /* fallthrough */ }
        return "10.10.0.2/32";
    }

    private static WgPeerFormViewModel FromEntity(WgPeer p) => new()
    {
        Id = p.Id, ServerId = p.ServerId, Name = p.Name,
        AllowedIpsRaw = string.Join(", ", p.AllowedIps),
        PersistentKeepalive = p.PersistentKeepalive,
        Endpoint = p.Endpoint,
        RouteMode = string.IsNullOrEmpty(p.RouteMode) ? "full" : p.RouteMode,
        AllowedSubnetsRaw = p.AllowedSubnets is { Length: > 0 } ? string.Join(", ", p.AllowedSubnets) : null,
        Description = p.Description, Enabled = p.Enabled,
        PresharedKey = p.PresharedKey
    };
}
