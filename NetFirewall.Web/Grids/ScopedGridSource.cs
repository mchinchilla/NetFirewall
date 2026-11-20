using NetOpenGrid.Application.DataSources;
using NetOpenGrid.Application.Options;
using NetOpenGrid.Domain.Abstractions;

namespace NetFirewall.Web.Grids;

/// <summary>
/// Data sources for grids whose rows come from an existing scoped service.
/// NetOpenGrid keeps each grid runtime as a keyed SINGLETON and hands the factory the root
/// provider, so the loader opens its own async scope per load and resolves the feature's
/// service interface there. SQL stays inside the services (project rule 10); the grid only
/// sees the rows and runs filter/sort/group/page over the snapshot with its precompiled
/// delegates.
/// </summary>
public static class ScopedGridSource
{
    public static IGridDataSource<TRow> From<TService, TRow>(
        IServiceProvider root,
        GridOptions<TRow> options,
        Func<TService, CancellationToken, Task<IReadOnlyList<TRow>>> load)
        where TService : notnull
    {
        ArgumentNullException.ThrowIfNull(load);
        var scopes = root.GetRequiredService<IServiceScopeFactory>();
        return new InMemoryGridDataSource<TRow>(options, async ct =>
        {
            await using var scope = scopes.CreateAsyncScope();
            return await load(scope.ServiceProvider.GetRequiredService<TService>(), ct);
        });
    }
}
