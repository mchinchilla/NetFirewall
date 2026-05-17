using NetFirewall.Models.Vpn;

namespace NetFirewall.Services.Vpn;

/// <summary>
/// Reads an existing wg-quick config file from disk and upserts the resulting
/// <see cref="WgServer"/> + <see cref="WgPeer"/> rows into the database.
///
/// Single direction: disk → DB. The reverse (DB → disk) is what
/// <see cref="IWireGuardApplyService"/> already does.
///
/// Used to onboard a firewall that already had wg0 configured by hand
/// (or by another tool) without losing the running tunnel — once imported,
/// the daemon can keep regenerating the same config from the DB.
/// </summary>
public interface IWireGuardImporter
{
    /// <summary>
    /// List wg-quick configs visible under the config dir (default
    /// <c>/etc/wireguard</c>) — file basenames without the <c>.conf</c> suffix.
    /// </summary>
    Task<IReadOnlyList<string>> ListAvailableAsync(CancellationToken ct = default);

    /// <summary>
    /// Parse <c>{ConfigDir}/{name}.conf</c> and upsert into <c>wg_servers</c> +
    /// <c>wg_peers</c>. Returns the resulting server + peers exactly as they
    /// landed in the DB (idempotent on re-import — peers matched by
    /// public_key, server matched by name).
    /// </summary>
    Task<WireGuardImportResult> ImportAsync(string interfaceName, CancellationToken ct = default);
}

public sealed record WireGuardImportResult(
    WgServer Server,
    IReadOnlyList<WgPeer> Peers,
    string Mode,         // "server" or "client" — what the parser inferred
    string SourcePath);
