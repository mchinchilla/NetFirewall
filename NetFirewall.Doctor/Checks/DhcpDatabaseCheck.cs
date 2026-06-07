using Npgsql;

namespace NetFirewall.Doctor.Checks;

/// <summary>
/// The DHCP server's OWN connection string reaches PostgreSQL and sees the lease
/// schema. The DHCP service has an independent connection string (its appsettings.json,
/// optionally overridden by dhcp.env) that can drift from the daemon/web one — a
/// wrong host/password here means leases silently fail to persist while the rest of
/// the stack looks healthy. Separate from <see cref="DatabaseCheck"/> on purpose.
/// </summary>
public sealed class DhcpDatabaseCheck : ICheck
{
    public string Category => "Database";
    public string Name => "DHCP DB reachable";
    public IReadOnlyList<string> Services => new[] { "dhcp" };

    public async Task<CheckResult> RunAsync(DoctorContext ctx, CancellationToken ct)
    {
        var conn = ctx.DhcpConnectionString;
        if (string.IsNullOrWhiteSpace(conn) || conn.Contains("__REPLACE__"))
            return CheckResult.Skip("no DHCP connection string (see DHCP Configuration check)");

        try
        {
            await using var c = new NpgsqlConnection(conn);
            await c.OpenAsync(ct);

            var hasLeases = (bool?)await new NpgsqlCommand(
                "SELECT to_regclass('public.dhcp_leases') IS NOT NULL", c).ExecuteScalarAsync(ct) ?? false;

            if (!hasLeases)
                return CheckResult.Warn(
                    "DHCP DB connected, but dhcp_leases table is absent",
                    remedy: "Apply the schema (bin/db.sh up). Confirm the DHCP connection string targets the net_firewall database.");

            return CheckResult.Pass("DHCP connection string reaches PostgreSQL; dhcp_leases present");
        }
        catch (Exception ex)
        {
            return CheckResult.Fail($"DHCP DB unreachable: {ex.Message}",
                remedy: $"Fix ConnectionStrings:DefaultConnection in {ctx.DhcpDir}/appsettings.json (or {ctx.DhcpEnvPath}).");
        }
    }
}
