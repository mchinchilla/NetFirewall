using Microsoft.Extensions.Logging;
using Npgsql;

namespace NetFirewall.Services.Database;

/// <summary>
/// Fail-soft helpers for queries that touch tables which may not exist yet on
/// a given deployment (e.g. a host whose schema migrations are behind the code,
/// as observed on tekium where 00021–00033 were never applied and every
/// <c>vpn-health</c> read threw <c>42P01: relation "vpn_health_state" does not
/// exist</c> on a 30s loop).
///
/// PostgreSQL reports a missing relation with SQLSTATE <c>42P01</c>
/// (undefined_table). Rather than 500 the caller or crash a background loop,
/// reads degrade to an empty result and writes become no-ops — both logged once
/// per occurrence at Warning. As soon as the migration is applied the queries
/// succeed again with no code change. This is intentionally narrow: ONLY the
/// undefined-table state is swallowed; every other Postgres error propagates.
/// </summary>
public static class MissingTableGuard
{
    /// <summary>PostgreSQL SQLSTATE for "relation does not exist".</summary>
    public const string UndefinedTable = "42P01";

    private static bool IsMissingTable(Exception ex) =>
        ex is PostgresException pg && pg.SqlState == UndefinedTable;

    /// <summary>
    /// Run a read that returns a list; if the underlying table is missing,
    /// return an empty list instead of throwing.
    /// </summary>
    public static async Task<IReadOnlyList<T>> ReadListAsync<T>(
        Func<Task<IReadOnlyList<T>>> read,
        ILogger logger,
        string what)
    {
        try
        {
            return await read();
        }
        catch (Exception ex) when (IsMissingTable(ex))
        {
            logger.LogWarning(
                "{What}: backing table not found ({Sql}) — returning empty. " +
                "A schema migration is likely pending on this host.",
                what, UndefinedTable);
            return Array.Empty<T>();
        }
    }

    /// <summary>
    /// Run a write (upsert / insert / update); if the underlying table is
    /// missing, swallow it as a no-op so a background loop keeps running.
    /// </summary>
    public static async Task WriteAsync(
        Func<Task> write,
        ILogger logger,
        string what)
    {
        try
        {
            await write();
        }
        catch (Exception ex) when (IsMissingTable(ex))
        {
            logger.LogWarning(
                "{What}: backing table not found ({Sql}) — skipping write. " +
                "A schema migration is likely pending on this host.",
                what, UndefinedTable);
        }
    }
}
