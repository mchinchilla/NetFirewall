using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Vpn;
using Npgsql;

namespace NetFirewall.Services.Vpn;

/// <summary>
/// Disk → DB: parses <c>/etc/wireguard/{name}.conf</c> (the wg-quick format)
/// and upserts wg_servers + wg_peers. Idempotent (matches server by name, peer
/// by public_key). Pure data import — does NOT touch the running interface.
/// </summary>
public sealed class WireGuardImporter : IWireGuardImporter
{
    private readonly IWireGuardService _wg;
    private readonly IWireGuardApplyService _apply;
    private readonly NpgsqlDataSource _db;
    private readonly ILogger<WireGuardImporter> _logger;
    private readonly string _configDir;

    public WireGuardImporter(
        IWireGuardService wg,
        IWireGuardApplyService apply,
        NpgsqlDataSource db,
        ILogger<WireGuardImporter> logger,
        IOptions<WireGuardApplyOptions> opts)
    {
        _wg = wg;
        _apply = apply;
        _db = db;
        _logger = logger;
        _configDir = opts.Value.ConfigDir;
    }

    public Task<IReadOnlyList<string>> ListAvailableAsync(CancellationToken ct = default)
    {
        if (!Directory.Exists(_configDir))
            return Task.FromResult<IReadOnlyList<string>>(Array.Empty<string>());

        var names = Directory.EnumerateFiles(_configDir, "*.conf")
            .Select(p => Path.GetFileNameWithoutExtension(p)!)
            .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        return Task.FromResult<IReadOnlyList<string>>(names);
    }

    public async Task<WireGuardImportResult> ImportAsync(string interfaceName, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(interfaceName))
            throw new ArgumentException("Interface name is required.", nameof(interfaceName));

        // wg-quick rejects names with '/' or '..' — be conservative.
        if (interfaceName.Contains('/') || interfaceName.Contains("..", StringComparison.Ordinal))
            throw new ArgumentException("Illegal interface name.", nameof(interfaceName));

        var path = Path.Combine(_configDir, interfaceName + ".conf");
        if (!File.Exists(path))
            throw new FileNotFoundException($"No such WireGuard config: {path}", path);

        var text = await File.ReadAllTextAsync(path, ct);
        var parsed = ParseWgQuick(text);

        // Mode is inferred: if [Interface] has ListenPort → 'server'. If it doesn't
        // (or there's exactly one peer with Endpoint set) → 'client'.
        var mode = parsed.Interface.ListenPort.HasValue ? "server" : "client";

        // Public key must be derived from private — wg-quick configs don't store it.
        var pubkey = await _apply.DerivePublicKeyAsync(parsed.Interface.PrivateKey, ct);

        // UPSERT wg_servers by name.
        var existing = await _wg.GetServerAsync(ct);  // single-server design today
        // Find by name explicitly even though the service returns 'first' —
        // when we support N servers this becomes the right path.
        var server = (existing != null && existing.Name == interfaceName) ? existing : new WgServer { Name = interfaceName };

        server.Mode        = mode;
        server.PrivateKey  = parsed.Interface.PrivateKey;
        server.PublicKey   = pubkey;
        server.ListenPort  = parsed.Interface.ListenPort ?? 0;  // 0 in client mode
        server.AddressCidr = parsed.Interface.Address ?? string.Empty;
        server.Dns         = parsed.Interface.Dns;
        server.Mtu         = parsed.Interface.Mtu;
        server.TableOff    = parsed.Interface.TableOff;
        server.PostUp      = parsed.Interface.PostUp;
        server.PostDown    = parsed.Interface.PostDown;
        server.Enabled     = true;

        await _wg.SaveServerAsync(server, ct);

        // UPSERT peers by public_key. Anything currently in DB for this server
        // that's NOT in the disk config gets deleted — disk is source of truth
        // during import. Operator already opted in by clicking Import.
        var existingPeers = await _wg.GetPeersAsync(server.Id, ct);
        var byPubKey = existingPeers.ToDictionary(p => p.PublicKey, StringComparer.Ordinal);

        var imported = new List<WgPeer>();
        foreach (var parsedPeer in parsed.Peers)
        {
            if (!byPubKey.TryGetValue(parsedPeer.PublicKey, out var peer))
            {
                peer = new WgPeer { ServerId = server.Id };
            }
            peer.Name                = parsedPeer.Name ?? $"peer-{parsedPeer.PublicKey[..8]}";
            peer.PublicKey           = parsedPeer.PublicKey;
            peer.PresharedKey        = parsedPeer.PresharedKey;
            peer.AllowedIps          = parsedPeer.AllowedIPs;
            peer.PersistentKeepalive = parsedPeer.PersistentKeepalive;
            peer.Endpoint            = parsedPeer.Endpoint;
            peer.Enabled             = true;

            if (peer.Id == Guid.Empty)
                await _wg.CreatePeerAsync(peer, ct);
            else
                await _wg.UpdatePeerAsync(peer, ct);

            imported.Add(peer);
            byPubKey.Remove(parsedPeer.PublicKey);
        }

        // Anything left in byPubKey is in DB but no longer in the config → drop.
        foreach (var stale in byPubKey.Values)
        {
            await _wg.DeletePeerAsync(stale.Id, ct);
            _logger.LogInformation("Imported wg config — dropped stale peer {Name} (pubkey {Pk})",
                stale.Name, stale.PublicKey[..8]);
        }

        _logger.LogInformation("Imported WireGuard config {Name} from {Path}: mode={Mode}, {N} peers",
            interfaceName, path, mode, imported.Count);

        return new WireGuardImportResult(server, imported, mode, path);
    }

    // ─────────────────────────────────── parser

    private sealed class InterfaceSection
    {
        public string PrivateKey { get; set; } = string.Empty;
        public string? Address   { get; set; }
        public int? ListenPort   { get; set; }
        public string? Dns       { get; set; }
        public int? Mtu          { get; set; }
        public bool TableOff     { get; set; }
        public string? PostUp    { get; set; }
        public string? PostDown  { get; set; }
    }

    private sealed class PeerSection
    {
        public string PublicKey = string.Empty;
        public string? PresharedKey;
        public string[] AllowedIPs = Array.Empty<string>();
        public string? Endpoint;
        public int? PersistentKeepalive;
        public string? Name;          // From "# Name = foo" comment, if present
    }

    private sealed class ParsedConfig
    {
        public InterfaceSection Interface { get; } = new();
        public List<PeerSection> Peers { get; } = new();
    }

    private static ParsedConfig ParseWgQuick(string text)
    {
        var cfg = new ParsedConfig();
        PeerSection? currentPeer = null;
        string section = "";
        string? pendingComment = null;

        foreach (var rawLine in text.Split('\n'))
        {
            var line = rawLine.TrimEnd('\r').Trim();
            if (line.Length == 0) { pendingComment = null; continue; }

            // Recognize "# Name = friendly-name" or "# friendly-name" before a [Peer]
            // so multiple peers from the same conf can be told apart on import.
            if (line.StartsWith('#'))
            {
                var body = line[1..].Trim();
                if (body.StartsWith("Name", StringComparison.OrdinalIgnoreCase))
                {
                    var eq = body.IndexOf('=');
                    if (eq > 0) pendingComment = body[(eq + 1)..].Trim();
                }
                else
                {
                    pendingComment = body;
                }
                continue;
            }

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                section = line[1..^1].Trim().ToLowerInvariant();
                if (section == "peer")
                {
                    currentPeer = new PeerSection { Name = pendingComment };
                    cfg.Peers.Add(currentPeer);
                }
                pendingComment = null;
                continue;
            }

            var eqIdx = line.IndexOf('=');
            if (eqIdx <= 0) continue;
            var key = line[..eqIdx].Trim();
            var value = line[(eqIdx + 1)..].Trim();
            // Strip inline comments after #
            var hash = value.IndexOf('#');
            if (hash >= 0) value = value[..hash].Trim();
            if (value.Length == 0) continue;

            if (section == "interface")
            {
                switch (key.ToLowerInvariant())
                {
                    case "privatekey":  cfg.Interface.PrivateKey = value; break;
                    case "address":     cfg.Interface.Address    = value; break;
                    case "listenport":  if (int.TryParse(value, out var lp)) cfg.Interface.ListenPort = lp; break;
                    case "dns":         cfg.Interface.Dns        = value; break;
                    case "mtu":         if (int.TryParse(value, out var mtu)) cfg.Interface.Mtu = mtu; break;
                    case "table":       cfg.Interface.TableOff = value.Equals("off", StringComparison.OrdinalIgnoreCase); break;
                    case "postup":      cfg.Interface.PostUp   = value; break;
                    case "postdown":    cfg.Interface.PostDown = value; break;
                }
            }
            else if (section == "peer" && currentPeer is not null)
            {
                switch (key.ToLowerInvariant())
                {
                    case "publickey":    currentPeer.PublicKey    = value; break;
                    case "presharedkey": currentPeer.PresharedKey = value; break;
                    case "allowedips":   currentPeer.AllowedIPs   = value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries); break;
                    case "endpoint":     currentPeer.Endpoint     = value; break;
                    case "persistentkeepalive": if (int.TryParse(value, out var pk)) currentPeer.PersistentKeepalive = pk; break;
                }
            }
        }

        if (string.IsNullOrEmpty(cfg.Interface.PrivateKey))
            throw new InvalidOperationException("Config missing [Interface] PrivateKey.");

        // Drop incomplete peers (no PublicKey is a parse error in real configs).
        cfg.Peers.RemoveAll(p => string.IsNullOrEmpty(p.PublicKey));

        return cfg;
    }
}
