using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Services.Search;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Search;

/// <summary>
/// Real-Postgres coverage for <see cref="SearchService"/>. Drives the full-text
/// pipeline: insert into search_index (the trigger-maintained table), then
/// query via websearch_to_tsquery and verify the rank-ordered results.
///
/// We bypass the per-source triggers (filter rules, NAT, etc.) by inserting
/// directly into search_index — that's the contract the service depends on,
/// and the trigger plumbing has its own integration story.
/// </summary>
[Collection("Postgres")]
public sealed class SearchServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private SearchService _svc = null!;

    public SearchServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        // Migration 20 (network_services) seeds ~70 rows whose triggers populate
        // the search_index. Wipe it so our own seeds are the only matches.
        await using (var conn = await _pg.DataSource.OpenConnectionAsync())
        await using (var cmd = new NpgsqlCommand("TRUNCATE TABLE search_index", conn))
            await cmd.ExecuteNonQueryAsync();

        _svc = new SearchService(_pg.DataSource, NullLogger<SearchService>.Instance);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    /// <summary>
    /// Insert one row into search_index. Uses the same <c>search_make_tsv</c>
    /// helper the production triggers call, so weighting matches reality.
    /// </summary>
    private async Task SeedAsync(string entityType, string title, string? subtitle = null,
        string? description = null, string? extra = null, string url = "/x")
    {
        await using var conn = await _pg.DataSource.OpenConnectionAsync();
        await using var cmd = new NpgsqlCommand(@"
            INSERT INTO search_index (entity_type, entity_id, title, subtitle, url, tsv, updated_at)
            VALUES (@type, gen_random_uuid(), @title, @subtitle, @url,
                    search_make_tsv(@a::text, @b::text, @c::text, @d::text),
                    now())", conn);
        cmd.Parameters.AddWithValue("type", entityType);
        cmd.Parameters.AddWithValue("title", title);
        cmd.Parameters.AddWithValue("subtitle", (object?)subtitle ?? DBNull.Value);
        cmd.Parameters.AddWithValue("url", url);
        cmd.Parameters.AddWithValue("a", title);
        cmd.Parameters.AddWithValue("b", (object?)subtitle ?? DBNull.Value);
        cmd.Parameters.AddWithValue("c", (object?)description ?? DBNull.Value);
        cmd.Parameters.AddWithValue("d", (object?)extra ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync();
    }

    // ── empty / null query short-circuit ───────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public async Task Search_EmptyOrNullQuery_ReturnsEmpty_NoDbHit(string? q)
    {
        // Even with rows present, empty query yields nothing.
        await SeedAsync("filter_rule", "Allow SSH");
        Assert.Empty(await _svc.SearchAsync(q));
    }

    // ── basic tsv match ────────────────────────────────────────────────

    [Fact]
    public async Task Search_TitleMatch_ReturnsHit()
    {
        await SeedAsync("filter_rule", "Allow SSH from LAN", url: "/Firewall/FilterRules/edit/abc");

        var hits = await _svc.SearchAsync("ssh");
        var hit = Assert.Single(hits);

        Assert.Equal("filter_rule", hit.EntityType);
        Assert.Equal("Allow SSH from LAN", hit.Title);
        Assert.Equal("/Firewall/FilterRules/edit/abc", hit.Url);
        Assert.True(hit.Rank > 0);
    }

    [Fact]
    public async Task Search_SubtitleMatch_RanksBelowTitle()
    {
        // Two hits for "lan": one in title (weight A), one in subtitle (weight B).
        // The title-match should rank higher.
        await SeedAsync("filter_rule", "Allow LAN clients",          url: "/a");
        await SeedAsync("filter_rule", "Allow SSH",      "from LAN", url: "/b");

        var hits = await _svc.SearchAsync("lan");

        Assert.Equal(2, hits.Count);
        Assert.Equal("Allow LAN clients", hits[0].Title); // title-weighted wins
        Assert.True(hits[0].Rank >= hits[1].Rank);
    }

    [Fact]
    public async Task Search_NoMatches_ReturnsEmpty()
    {
        await SeedAsync("filter_rule", "Allow SSH");
        Assert.Empty(await _svc.SearchAsync("dropbox-cloud-thing"));
    }

    // ── websearch_to_tsquery semantics ─────────────────────────────────

    [Fact]
    public async Task Search_QuotedPhrase_RequiresAdjacentTokens()
    {
        await SeedAsync("filter_rule", "Allow SSH access", url: "/a");
        await SeedAsync("filter_rule", "SSH and HTTP",     url: "/b");

        // "Allow SSH" as a phrase only matches the first row.
        var hits = await _svc.SearchAsync("\"Allow SSH\"");
        var hit = Assert.Single(hits);
        Assert.Equal("Allow SSH access", hit.Title);
    }

    [Fact]
    public async Task Search_NegatedTerm_ExcludesMatchingRows()
    {
        await SeedAsync("filter_rule", "Allow SSH",  url: "/a");
        await SeedAsync("filter_rule", "Allow HTTP", url: "/b");

        var hits = await _svc.SearchAsync("allow -ssh");

        var hit = Assert.Single(hits);
        Assert.Equal("Allow HTTP", hit.Title);
    }

    // ── limit and ordering ────────────────────────────────────────────

    [Fact]
    public async Task Search_RespectsLimit()
    {
        for (var i = 0; i < 25; i++)
            await SeedAsync("filter_rule", $"Allow item-{i}");

        var hits = await _svc.SearchAsync("allow", limit: 5);
        Assert.Equal(5, hits.Count);
    }

    [Fact]
    public async Task Search_TiesBrokenByUpdatedAtDesc()
    {
        // Two equally-ranked rows; the one inserted later (newer updated_at) should appear first.
        await SeedAsync("filter_rule", "Allow tag-marker", url: "/older");
        await Task.Delay(20);
        await SeedAsync("filter_rule", "Allow tag-marker", url: "/newer");

        var hits = await _svc.SearchAsync("tag-marker");

        Assert.Equal(2, hits.Count);
        Assert.Equal("/newer", hits[0].Url);
        Assert.Equal("/older", hits[1].Url);
    }

    // ── multi-entity-type results ──────────────────────────────────────

    [Fact]
    public async Task Search_AcrossEntityTypes_ReturnsAllMatches()
    {
        await SeedAsync("filter_rule",   "marker FR");
        await SeedAsync("network_object","marker NO");
        await SeedAsync("dhcp_subnet",   "marker DS");

        var hits = await _svc.SearchAsync("marker");

        Assert.Equal(3, hits.Count);
        Assert.Contains(hits, h => h.EntityType == "filter_rule");
        Assert.Contains(hits, h => h.EntityType == "network_object");
        Assert.Contains(hits, h => h.EntityType == "dhcp_subnet");
    }

    // ── failure tolerance ─────────────────────────────────────────────

    [Fact]
    public async Task Search_SearchIndexTableMissing_ReturnsEmpty_NoCrash()
    {
        await using (var conn = await _pg.DataSource.OpenConnectionAsync())
        await using (var cmd = new NpgsqlCommand("DROP TABLE IF EXISTS search_index CASCADE", conn))
            await cmd.ExecuteNonQueryAsync();

        Assert.Empty(await _svc.SearchAsync("anything"));
    }
}
