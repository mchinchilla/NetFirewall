using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NetFirewall.Models.Vpn;
using NetFirewall.Services.Firewall;
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

public sealed class WireGuardApplyService : IWireGuardApplyService
{
    private readonly IWireGuardConfigService _config;
    private readonly IProcessRunner _runner;
    private readonly ILogger<WireGuardApplyService> _logger;
    private readonly WireGuardApplyOptions _options;

    public WireGuardApplyService(
        IWireGuardConfigService config,
        IProcessRunner runner,
        ILogger<WireGuardApplyService> logger,
        IOptions<WireGuardApplyOptions>? options = null)
    {
        _config = config;
        _runner = runner;
        _logger = logger;
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

            // If the iface is already up, hot-reload (preserves handshakes).
            // Otherwise bring it up cold.
            var script = $"set -euo pipefail; if ip link show {server.Name} >/dev/null 2>&1; then " +
                         $"wg syncconf {server.Name} <(wg-quick strip {server.Name}); " +
                         $"else wg-quick up {server.Name}; fi";
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

    public async Task<IReadOnlyList<WgPeerLiveStatus>> GetStatusAsync(string interfaceName, CancellationToken ct = default)
    {
        // `wg show <iface> dump` — tab-separated:
        //   line 1 (interface): priv \t pub \t listen_port \t fwmark
        //   line N (peers):     pub \t psk \t endpoint \t allowed_ips \t handshake_unix \t rx \t tx \t keepalive
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

        var lines = result.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries);
        var peers = new List<WgPeerLiveStatus>();
        foreach (var line in lines.Skip(1)) // skip interface line
        {
            var f = line.Split('\t');
            if (f.Length < 8) continue;

            var pub = f[0];
            var endpoint = f[2] == "(none)" ? null : f[2];
            DateTime? hs = long.TryParse(f[4], out var ts) && ts > 0
                ? DateTimeOffset.FromUnixTimeSeconds(ts).UtcDateTime
                : null;
            long.TryParse(f[5], out var rx);
            long.TryParse(f[6], out var tx);

            peers.Add(new WgPeerLiveStatus(pub, endpoint, hs, rx, tx));
        }
        return peers;
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
