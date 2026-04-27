using Microsoft.Extensions.Logging;
using Npgsql;

namespace NetFirewall.Services.Search;

public sealed class SearchService : ISearchService
{
    private readonly NpgsqlDataSource _ds;
    private readonly ILogger<SearchService> _logger;

    public SearchService(NpgsqlDataSource ds, ILogger<SearchService> logger)
    {
        _ds = ds;
        _logger = logger;
    }

    public async Task<IReadOnlyList<SearchHit>> SearchAsync(string? query, int limit = 20, CancellationToken ct = default)
    {
        var q = (query ?? string.Empty).Trim();
        if (string.IsNullOrEmpty(q)) return Array.Empty<SearchHit>();

        // websearch_to_tsquery handles user-friendly syntax: quoted phrases,
        // OR, leading -, etc. plainto_tsquery is too strict (no operators).
        const string sql = @"
            SELECT entity_type, entity_id, title, subtitle, url,
                   ts_rank(tsv, q) AS rank
              FROM search_index, websearch_to_tsquery('simple', @q) AS q
             WHERE tsv @@ q
             ORDER BY rank DESC, updated_at DESC
             LIMIT @lim";

        try
        {
            await using var conn = await _ds.OpenConnectionAsync(ct);
            await using var cmd = new NpgsqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("q", q);
            cmd.Parameters.AddWithValue("lim", limit);

            var hits = new List<SearchHit>();
            await using var reader = await cmd.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct))
            {
                hits.Add(new SearchHit(
                    EntityType: reader.GetString(0),
                    EntityId:   reader.GetGuid(1),
                    Title:      reader.GetString(2),
                    Subtitle:   reader.IsDBNull(3) ? null : reader.GetString(3),
                    Url:        reader.GetString(4),
                    Rank:       (double)reader.GetFloat(5)));
            }
            return hits;
        }
        catch (PostgresException ex) when (ex.SqlState == "42P01") // undefined_table
        {
            _logger.LogWarning("search_index missing — run migration 18. Returning empty results.");
            return Array.Empty<SearchHit>();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Search query failed for: {Query}", q);
            return Array.Empty<SearchHit>();
        }
    }
}
