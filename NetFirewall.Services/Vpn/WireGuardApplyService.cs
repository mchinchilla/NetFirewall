using System.Runtime.Versioning;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Firewall;
using NetFirewall.Services.Network;
using NetFirewall.Services.Processes;

namespace NetFirewall.Services.Vpn;

public sealed class WireGuardApplyOptions
{
    /// <summary>Where wg-quick reads configs from. Standard everywhere.</summary>
    public string ConfigDir { get; set; } = "/etc/wireguard";

    /// <summary>Path to bash on the host.</summary>
    public string BashPath { get; set; } = "/bin/bash";

    /// <summary>Hard cap so a stuck wg-quick can't hang the daemon.</summary>
    public int CommandTimeoutSeconds { get; set; } = 30;
}

[SupportedOSPlatform("linux")]
public sealed class WireGuardApplyService : IWireGuardApplyService
{
    private readonly IWireGuardConfigService _config;
    private readonly IProcessRunner _runner;
    private readonly INetworkLinkProbe? _links;
    private readonly ILogger<WireGuardApplyService> _logger;
    private readonly WireGuardApplyOptions _options;

    public WireGuardApplyService(
        IWireGuardConfigService config,
        IProcessRunner runner,
        ILogger<WireGuardApplyService> logger,
        IOptions<WireGuardApplyOptions>? options = null,
        INetworkLinkProbe? links = null)
    {
        _config = config;
        _runner = runner;
        _logger = logger;
        _links = links;
        _options = options?.Value ?? new WireGuardApplyOptions();
    }

    public async Task<(string Private, string Public)> GenerateKeyPairAsync(CancellationToken ct = default)
    {
        // wg genkey emits 44 chars of base64 to stdout; pipe into wg pubkey to derive.
        var script = "set -euo pipefail; PRIV=$(wg genkey); PUB=$(echo \"$PRIV\" | wg pubkey); echo \"$PRIV\"; echo \"$PUB\"";
        var result = await _runner.RunAsync(
            _options.BashPath,
            $"-c \"{script}\"",
            TimeSpan.FromSeconds(_options.CommandTimeoutSeconds),
            ct);

        if (!result.Success)
            throw new InvalidOperationException($"wg genkey failed (exit {result.ExitCode}): {result.Error}");

        var lines = result.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (lines.Length < 2)
            throw new InvalidOperationException("wg genkey did not return two lines (priv + pub).");

        return (lines[0], lines[1]);
    }

    public async Task<string> GeneratePresharedKeyAsync(CancellationToken ct = default)
    {
        var result = await _runner.RunAsync(
            "wg", "genpsk",
            TimeSpan.FromSeconds(_options.CommandTimeoutSeconds),
            ct);
        if (!result.Success)
            throw new InvalidOperationException($"wg genpsk failed (exit {result.ExitCode}): {result.Error}");
        return result.Output.Trim();
    }

    public async Task<string> DerivePublicKeyAsync(string privateKey, CancellationToken ct = default)
    {
        // wg pubkey reads the private key from stdin. We can't pipe via
        // IProcessRunner (no stdin support), so we wrap in bash and use a
        // single-quoted printf — the privkey appears briefly on the bash
        // arg list. Acceptable: importer is invoked once at onboarding, not
        // in a hot path, and the daemon already holds the key in memory.
        // Quotes around the key are safe because wg's base64 alphabet never
        // contains '.
        var sanitized = privateKey.Trim();
        if (sanitized.Contains('\'') || sanitized.Contains('\n'))
            throw new ArgumentException("Private key contains illegal characters.", nameof(privateKey));

        var script = $"printf '%s' '{sanitized}' | wg pubkey";
        var result = await _runner.RunAsync(
            _options.BashPath,
            $"-c \"{script}\"",
            TimeSpan.FromSeconds(_options.CommandTimeoutSeconds),
            ct);

        if (!result.Success)
            throw new InvalidOperationException($"wg pubkey failed (exit {result.ExitCode}): {result.Error}");
        return result.Output.Trim();
    }

    public async Task<NftApplyResult> ApplyAsync(WgServer server, IReadOnlyList<WgPeer> peers, CancellationToken ct = default)
    {
        try
        {
            Directory.CreateDirectory(_options.ConfigDir);

            var path = Path.Combine(_options.ConfigDir, $"{server.Name}.conf");
            var content = _config.GenerateServerConfig(server, peers);
            await File.WriteAllTextAsync(path, content, ct);
            try { File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite); }
            catch { /* not on a unix-y FS — fine */ }

            var script = BuildApplyScript(server.Name, server.AddressCidr, server.Mtu);
            var proc = await _runner.RunAsync(
                _options.BashPath,
                $"-c \"{script}\"",
                TimeSpan.FromSeconds(_options.CommandTimeoutSeconds),
                ct);

            _logger.LogInformation("wg apply {Name}: exit {Exit}", server.Name, proc.ExitCode);
            return new NftApplyResult
            {
                Success = proc.Success,
                ExitCode = proc.ExitCode,
                Output = proc.Output,
                Error = proc.Error
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "wg apply {Name} blew up before wg-quick could run", server.Name);
            return new NftApplyResult
            {
                Success = false,
                ExitCode = -1,
                Error = ex.Message
            };
        }
    }

    private static readonly Regex ShellInert = new(@"^[0-9./]+$", RegexOptions.Compiled);

    /// <summary>
    /// Bash for "make the live interface match the config". <c>wg syncconf</c>
    /// is the gentle path (peers/keys/port only — handshakes survive), but it
    /// can NOT change the interface address or MTU: those are wg-quick's job at
    /// <c>up</c>. So when the live address/MTU drift from the config we do a
    /// cold down/up — the only way the change reaches the kernel. (tekium: the
    /// address was saved as .2 but the box kept sourcing from .3 until a manual
    /// restart, and the remote server silently dropped every data packet.)
    /// Values are only embedded when provably shell-inert; anything odd skips
    /// drift detection and keeps the syncconf path. No double quotes anywhere:
    /// the script travels inside <c>bash -c "…"</c>.
    /// </summary>
    internal static string BuildApplyScript(string name, string addressCidr, int? mtu)
    {
        var up   = $"wg-quick up {name}";
        var sync = $"wg syncconf {name} <(wg-quick strip {name})";
        var cold = $"wg-quick down {name}; {up}";

        var checks = new List<string>();
        if (!string.IsNullOrEmpty(addressCidr) && ShellInert.IsMatch(addressCidr))
            checks.Add($"ip -4 -o addr show dev {name} | grep -qF 'inet {addressCidr} '");
        if (mtu is > 0)
            checks.Add($"ip -o link show dev {name} | grep -qw 'mtu {mtu}'");

        var whenUp = checks.Count == 0
            ? sync
            : $"if {string.Join(" && ", checks)}; then {sync}; else {cold}; fi";

        return $"set -euo pipefail; if ip link show {name} >/dev/null 2>&1; then {whenUp}; else {up}; fi";
    }

    public async Task<IReadOnlyList<WgPeerLiveStatus>> GetStatusAsync(string interfaceName, CancellationToken ct = default)
    {
        // `wg show <iface> dump` — tab-separated:
        //   line 1 (interface): priv \t pub \t listen_port \t fwmark
        //   line N (peers):     pub \t psk \t endpoint \t allowed_ips \t handshake_unix \t rx \t tx \t keepalive
        if (_links is not null && !_links.Exists(interfaceName))
        {
            // Tunnel intentionally down (Stop) or never created: no interface,
            // no peers. Skip the exec entirely — otherwise every status poll
            // (UI every few seconds + the health monitor) logs a WRN
            // "wg show … Unable to access interface: No such device" while the
            // operator has simply stopped the VPN.
            _logger.LogDebug("wg interface {Iface} is not present — reporting no live peers", interfaceName);
            return Array.Empty<WgPeerLiveStatus>();
        }

        var result = await _runner.RunAsync(
            "wg",
            $"show {interfaceName} dump",
            TimeSpan.FromSeconds(_options.CommandTimeoutSeconds),
            ct);

        if (!result.Success)
        {
            _logger.LogDebug("wg show {Iface} dump failed (exit {Exit}): {Err}",
                interfaceName, result.ExitCode, result.Error);
            return Array.Empty<WgPeerLiveStatus>();
        }

        // One parser for the dump format (shared with the diagnostics reader); it
        // drops the private/preshared keys, so nothing secret reaches callers.
        return WgDumpParser.Parse(result.Output).Peers
            .Select(p => new WgPeerLiveStatus(p.PublicKey, p.Endpoint, p.LatestHandshakeUtc, p.RxBytes, p.TxBytes))
            .ToList();
    }

    public async Task<NftApplyResult> StopAsync(string interfaceName, CancellationToken ct = default)
    {
        var proc = await _runner.RunAsync(
            "wg-quick",
            $"down {interfaceName}",
            TimeSpan.FromSeconds(_options.CommandTimeoutSeconds),
            ct);

        return new NftApplyResult
        {
            // wg-quick down returns non-zero when the iface isn't up; treat as idempotent success.
            Success = proc.Success || (proc.Error?.Contains("is not a WireGuard interface") ?? false),
            ExitCode = proc.ExitCode,
            Output = proc.Output,
            Error = proc.Error
        };
    }
}
