namespace NetFirewall.Services.Search;

/// <summary>
/// Full-text search across the firewall's entities. Backed by Postgres
/// <c>tsvector</c> + GIN indexes on a centralized <c>search_index</c> table
/// (one row per searchable entity, kept in sync via per-source triggers).
/// </summary>
public interface ISearchService
{
    /// <summary>
    /// Run a search. Empty / null query returns the empty list (we don't
    /// "show everything" — that's what the per-section list pages are for).
    /// Limit defaults to 20 — designed for the top-bar autocomplete dropdown.
    /// </summary>
    Task<IReadOnlyList<SearchHit>> SearchAsync(string? query, int limit = 20, CancellationToken ct = default);
}

/// <summary>One row in the dropdown / results page.</summary>
public sealed record SearchHit(
    string EntityType,
    Guid EntityId,
    string Title,
    string? Subtitle,
    string Url,
    double Rank);
