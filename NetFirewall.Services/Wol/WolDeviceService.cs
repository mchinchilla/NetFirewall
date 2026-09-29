using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using NetFirewall.Models;
using NetFirewall.Models.Wol;
using Npgsql;

namespace NetFirewall.Services.Wol;

public sealed partial class WolDeviceService : IWolDeviceService
{
    private const string SelectSql = """
        SELECT d.id, d.name, upper(d.mac_address::text), d.interface, d.port, d.description,
               d.last_woken_at, d.last_woken_by, d.created_at, d.updated_at,
               COALESCE(host(r.reserved_ip), host(l.ip_address)), l.hostname
          FROM wol_devices d
          LEFT JOIN dhcp_mac_reservations r ON r.mac_address = d.mac_address
          LEFT JOIN dhcp_leases l           ON l.mac_address = d.mac_address
        """;

    private readonly NpgsqlDataSource _ds;
    private readonly ILogger<WolDeviceService> _logger;

    public WolDeviceService(NpgsqlDataSource ds, ILogger<WolDeviceService> logger)
    {
        _ds = ds;
        _logger = logger;
    }

    public async Task<IReadOnlyList<WolDevice>> GetAllAsync(CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(SelectSql + " ORDER BY lower(d.name)", conn);
        return await ReadAsync(cmd, ct);
    }

    public async Task<WolDevice?> GetByIdAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(SelectSql + " WHERE d.id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        return (await ReadAsync(cmd, ct)).FirstOrDefault();
    }

    public async Task<ServiceResponse<WolDevice>> SaveAsync(WolDevice device, CancellationToken ct = default)
    {
        if (Validate(device) is { } invalid) return ServiceResponse<WolDevice>.Fail(invalid);

        var isNew = device.Id == Guid.Empty;
        var id = isNew ? Guid.NewGuid() : device.Id;
        const string insert = """
            INSERT INTO wol_devices (id, name, mac_address, interface, port, description, created_at, updated_at)
            VALUES (@id, @name, @mac::macaddr, @iface, @port, @descr, now(), now())
            """;
        const string update = """
            UPDATE wol_devices
               SET name = @name, mac_address = @mac::macaddr, interface = @iface, port = @port,
                   description = @descr, updated_at = now()
             WHERE id = @id
            """;

        try
        {
            await using var conn = await _ds.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(isNew ? insert : update, conn);
            cmd.Parameters.AddWithValue("id", id);
            cmd.Parameters.AddWithValue("name", device.Name);
            cmd.Parameters.AddWithValue("mac", device.MacAddress);
            cmd.Parameters.AddWithValue("iface", device.Interface);
            cmd.Parameters.AddWithValue("port", device.Port);
            cmd.Parameters.AddWithValue("descr", (object?)device.Description ?? DBNull.Value);
            if (await cmd.ExecuteNonQueryAsync(ct) == 0)
                return ServiceResponse<WolDevice>.Fail("Device not found. It may have been deleted.");
        }
        catch (PostgresException ex) when (ex.SqlState == PostgresErrorCodes.UniqueViolation)
        {
            return ServiceResponse<WolDevice>.Fail(ex.ConstraintName == "idx_wol_devices_name"
                ? $"Another device is already named '{device.Name}'."
                : $"{device.MacAddress} is already saved as another device.");
        }

        _logger.LogInformation("Wake-on-LAN device {Action}: {Name} ({Mac})", isNew ? "created" : "updated", device.Name, device.MacAddress);
        var saved = await GetByIdAsync(id, ct);
        return saved is null
            ? ServiceResponse<WolDevice>.Fail("Device not found. It may have been deleted.")
            : ServiceResponse<WolDevice>.Ok(saved, $"Device '{saved.Name}' saved.");
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand("DELETE FROM wol_devices WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        return await cmd.ExecuteNonQueryAsync(ct) > 0;
    }

    public async Task MarkWokenAsync(Guid id, string? by, CancellationToken ct = default)
    {
        await using var conn = await _ds.OpenConnectionAsync(ct);
        await using var cmd = new NpgsqlCommand(
            "UPDATE wol_devices SET last_woken_at = now(), last_woken_by = @by WHERE id = @id", conn);
        cmd.Parameters.AddWithValue("id", id);
        cmd.Parameters.AddWithValue("by", (object?)by ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    /// <summary>
    /// Service-layer guard (the form checks the same things first). Normalises the
    /// device in place — trimmed name, canonical MAC — and returns the first problem.
    /// </summary>
    internal static string? Validate(WolDevice d)
    {
        d.Name = (d.Name ?? string.Empty).Trim();
        if (d.Name.Length is 0 or > 64) return "Name is required (up to 64 characters).";

        if (!MacAddressText.TryParse(d.MacAddress, out _, out var mac, out var macError)) return macError;
        d.MacAddress = mac;

        d.Interface = (d.Interface ?? string.Empty).Trim();
        if (!IfaceRx().IsMatch(d.Interface)) return "Interface: 1-15 chars of letters, digits, '.', '_' or '-'.";

        if (d.Port is < 1 or > 65535) return "Port must be 1-65535.";

        d.Description = string.IsNullOrWhiteSpace(d.Description) ? null : d.Description.Trim();
        if (d.Description is { Length: > 255 }) return "Description: up to 255 characters.";
        return null;
    }

    private static async Task<IReadOnlyList<WolDevice>> ReadAsync(NpgsqlCommand cmd, CancellationToken ct)
    {
        var list = new List<WolDevice>();
        await using var r = await cmd.ExecuteReaderAsync(ct);
        while (await r.ReadAsync(ct))
        {
            list.Add(new WolDevice
            {
                Id            = r.GetGuid(0),
                Name          = r.GetString(1),
                MacAddress    = r.GetString(2),
                Interface     = r.GetString(3),
                Port          = r.GetInt32(4),
                Description   = r.IsDBNull(5) ? null : r.GetString(5),
                LastWokenAt   = r.IsDBNull(6) ? null : r.GetDateTime(6),
                LastWokenBy   = r.IsDBNull(7) ? null : r.GetString(7),
                CreatedAt     = r.GetDateTime(8),
                UpdatedAt     = r.GetDateTime(9),
                KnownIp       = r.IsDBNull(10) ? null : r.GetString(10),
                KnownHostname = r.IsDBNull(11) ? null : r.GetString(11),
            });
        }
        return list;
    }

    [GeneratedRegex(@"^[A-Za-z0-9_.\-]{1,15}$")]
    private static partial Regex IfaceRx();
}
