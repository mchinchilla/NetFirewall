using Microsoft.Extensions.Logging.Abstractions;
using NetFirewall.Models.Network;
using NetFirewall.Services.Network;
using NetFirewall.Tests.Infra;
using Npgsql;
using Xunit;

namespace NetFirewall.Tests.Network;

/// <summary>
/// Real-Postgres CRUD coverage for <see cref="NetworkObjectService"/>.
/// Resolver semantics (group expansion, FQDN cache) live in
/// <c>NetworkObjectResolverTests</c>; here we exercise persistence,
/// validation, group-member management, and the "where used" cross-table scan.
/// </summary>
[Collection("Postgres")]
public sealed class NetworkObjectServiceTests : IAsyncLifetime
{
    private readonly PostgresFixture _pg;
    private NetworkObjectService _svc = null!;

    public NetworkObjectServiceTests(PostgresFixture pg) => _pg = pg;

    public async Task InitializeAsync()
    {
        await _pg.ResetSchemaAsync();
        await _pg.BootstrapApplicationSchemaAsync();
        _svc = new NetworkObjectService(_pg.DataSource, NullLogger<NetworkObjectService>.Instance);
    }

    public Task DisposeAsync() => Task.CompletedTask;

    private static NetworkObject Host(string name, string ip) =>
        new() { Name = name, Type = NetworkObjectTypes.Host, Value = ip };

    // ── CRUD round-trip ────────────────────────────────────────────────

    [Fact]
    public async Task CreateAsync_PersistsAndReturnsRow_WithNewId()
    {
        var created = await _svc.CreateAsync(Host("Workstation", "10.0.0.5"));

        Assert.NotEqual(Guid.Empty, created.Id);
        var fetched = await _svc.GetByIdAsync(created.Id);
        Assert.NotNull(fetched);
        Assert.Equal("Workstation", fetched!.Name);
        Assert.Equal("host", fetched.Type);
        Assert.Equal("10.0.0.5", fetched.Value);
    }

    [Fact]
    public async Task GetByNameAsync_LookupByExactName_AndNullForUnknown()
    {
        var created = await _svc.CreateAsync(Host("Server", "1.2.3.4"));
        Assert.Equal(created.Id, (await _svc.GetByNameAsync("Server"))?.Id);
        Assert.Null(await _svc.GetByNameAsync("Unknown"));
    }

    [Fact]
    public async Task UpdateAsync_PersistsChanges()
    {
        var c = await _svc.CreateAsync(Host("Workstation", "10.0.0.5"));
        c.Value = "10.0.0.99";
        c.Description = "renumbered";
        await _svc.UpdateAsync(c);

        var fetched = await _svc.GetByIdAsync(c.Id);
        Assert.Equal("10.0.0.99", fetched!.Value);
        Assert.Equal("renumbered", fetched.Description);
    }

    [Fact]
    public async Task DeleteAsync_RemovesRow_AndReturnsTrue_FalseForUnknown()
    {
        var c = await _svc.CreateAsync(Host("Doomed", "10.0.0.6"));

        Assert.True(await _svc.DeleteAsync(c.Id));
        Assert.Null(await _svc.GetByIdAsync(c.Id));
        Assert.False(await _svc.DeleteAsync(Guid.NewGuid()));
    }

    // ── Validation ─────────────────────────────────────────────────────

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    public async Task CreateAsync_EmptyName_Throws(string name)
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            _svc.CreateAsync(new NetworkObject { Name = name, Type = "host", Value = "1.1.1.1" }));
    }

    [Fact]
    public async Task CreateAsync_InvalidType_Throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            _svc.CreateAsync(new NetworkObject { Name = "x", Type = "godmode", Value = "1.1.1.1" }));
    }

    [Theory]
    [InlineData(NetworkObjectTypes.Host)]
    [InlineData(NetworkObjectTypes.Network)]
    [InlineData(NetworkObjectTypes.Range)]
    [InlineData(NetworkObjectTypes.Fqdn)]
    public async Task CreateAsync_NonGroupTypeMissingValue_Throws(string type)
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            _svc.CreateAsync(new NetworkObject { Name = "x", Type = type, Value = "" }));
    }

    [Fact]
    public async Task CreateAsync_GroupTypeWithEmptyValue_IsAllowed()
    {
        var grp = await _svc.CreateAsync(new NetworkObject
        {
            Name = "EmptyGroup", Type = NetworkObjectTypes.Group, Value = ""
        });
        Assert.NotEqual(Guid.Empty, grp.Id);
    }

    // ── Group membership ───────────────────────────────────────────────

    [Fact]
    public async Task SetGroupMembersAsync_RejectsNonGroupParent()
    {
        var leaf = await _svc.CreateAsync(Host("Leaf", "10.0.0.5"));

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            _svc.SetGroupMembersAsync(leaf.Id, new[] { Guid.NewGuid() }));
    }

    [Fact]
    public async Task SetGroupMembersAsync_StoresMembers_AndIncludeMembersLoadsThem()
    {
        var web   = await _svc.CreateAsync(Host("Web",   "10.0.0.10"));
        var mail  = await _svc.CreateAsync(Host("Mail",  "10.0.0.11"));
        var grp   = await _svc.CreateAsync(new NetworkObject { Name = "Servers", Type = "group", Value = "" });

        await _svc.SetGroupMembersAsync(grp.Id, new[] { web.Id, mail.Id });

        var loaded = await _svc.GetByIdAsync(grp.Id, includeMembers: true);
        Assert.NotNull(loaded?.Members);
        Assert.Equal(2, loaded!.Members!.Count);
        Assert.Contains(loaded.Members, m => m.Name == "Web");
        Assert.Contains(loaded.Members, m => m.Name == "Mail");
    }

    [Fact]
    public async Task SetGroupMembersAsync_DropsParentSelfReference()
    {
        var grp = await _svc.CreateAsync(new NetworkObject { Name = "G", Type = "group", Value = "" });
        var leaf = await _svc.CreateAsync(Host("Leaf", "10.0.0.5"));

        // Including grp.Id in its own members must be silently dropped.
        await _svc.SetGroupMembersAsync(grp.Id, new[] { grp.Id, leaf.Id });

        var loaded = await _svc.GetByIdAsync(grp.Id, includeMembers: true);
        Assert.Single(loaded!.Members!);
        Assert.Equal("Leaf", loaded.Members![0].Name);
    }

    [Fact]
    public async Task SetGroupMembersAsync_ReplacesPriorMembership()
    {
        var grp  = await _svc.CreateAsync(new NetworkObject { Name = "G", Type = "group", Value = "" });
        var l1   = await _svc.CreateAsync(Host("L1", "10.0.0.1"));
        var l2   = await _svc.CreateAsync(Host("L2", "10.0.0.2"));
        var l3   = await _svc.CreateAsync(Host("L3", "10.0.0.3"));

        await _svc.SetGroupMembersAsync(grp.Id, new[] { l1.Id, l2.Id });
        await _svc.SetGroupMembersAsync(grp.Id, new[] { l3.Id }); // replaces

        var loaded = await _svc.GetByIdAsync(grp.Id, includeMembers: true);
        Assert.Single(loaded!.Members!);
        Assert.Equal("L3", loaded.Members![0].Name);
    }

    // ── FindUsages ─────────────────────────────────────────────────────

    [Fact]
    public async Task FindUsagesAsync_ReportsGroupParents()
    {
        var leaf = await _svc.CreateAsync(Host("Leaf", "10.0.0.5"));
        var grp  = await _svc.CreateAsync(new NetworkObject { Name = "Parent", Type = "group", Value = "" });
        await _svc.SetGroupMembersAsync(grp.Id, new[] { leaf.Id });

        var usage = await _svc.FindUsagesAsync("Leaf");

        var parent = Assert.Single(usage.ParentGroups);
        Assert.Equal(grp.Id, parent.Id);
        Assert.Equal("members", parent.Field);
    }

    [Fact]
    public async Task FindUsagesAsync_ReportsFilterRulesByName()
    {
        await _svc.CreateAsync(Host("Server", "10.0.0.10"));
        // Insert a filter rule that references "Server" by name in source_addresses.
        await using (var conn = await _pg.DataSource.OpenConnectionAsync())
        await using (var cmd = new NpgsqlCommand(@"
            INSERT INTO fw_filter_rules (id, chain, action, source_addresses, enabled, created_at)
            VALUES (gen_random_uuid(), 'input', 'accept', ARRAY['Server'], true, now())", conn))
            await cmd.ExecuteNonQueryAsync();

        var usage = await _svc.FindUsagesAsync("Server");
        Assert.Single(usage.FilterRules);
        Assert.Equal("source_addresses", usage.FilterRules[0].Field);
        Assert.Equal(1, usage.TotalCount);
    }

    [Fact]
    public async Task FindUsagesAsync_ReturnsEmptyForUnusedObject()
    {
        await _svc.CreateAsync(Host("Lonely", "10.0.0.99"));
        var usage = await _svc.FindUsagesAsync("Lonely");
        Assert.Equal(0, usage.TotalCount);
    }
}
