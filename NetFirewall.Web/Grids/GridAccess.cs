using System.Security.Claims;

namespace NetFirewall.Web.Grids;

/// <summary>
/// Who may read which grid. <c>MapNetOpenGrid</c> serves every grid from one route group
/// (<c>/netgrid/{gridId}</c>, <c>/rows</c>, <c>/values</c>, <c>/export</c>), so the MVC
/// <c>[Authorize(Roles = …)]</c> on each feature controller does not cover it. Each grid
/// declares the same roles as the controller of its page, and an endpoint filter checks them
/// on every grid request. Fail-closed: a grid id nobody registered is refused.
/// </summary>
public interface IGridAccessPolicy
{
    bool IsAllowed(string? gridId, ClaimsPrincipal user);
}

public sealed class GridAccessPolicy : IGridAccessPolicy
{
    private readonly Dictionary<string, string[]> _roles = new(StringComparer.Ordinal);

    public void Register(string gridId, params string[] roles)
    {
        if (roles.Length == 0) throw new ArgumentException($"Grid '{gridId}' must declare at least one role.", nameof(roles));
        if (!_roles.TryAdd(gridId, roles)) throw new InvalidOperationException($"Grid '{gridId}' is registered twice.");
    }

    public IReadOnlyCollection<string> GridIds => _roles.Keys;

    public bool IsAllowed(string? gridId, ClaimsPrincipal user)
    {
        if (gridId is null || user.Identity?.IsAuthenticated != true) return false;
        if (!_roles.TryGetValue(gridId, out var roles)) return false;
        foreach (var role in roles)
        {
            if (user.IsInRole(role)) return true;
        }
        return false;
    }
}

/// <summary>Applies <see cref="IGridAccessPolicy"/> to the NetOpenGrid route group.</summary>
public sealed class GridAccessEndpointFilter(IGridAccessPolicy policy) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        var http = context.HttpContext;
        var gridId = http.GetRouteValue("gridId") as string;
        if (!policy.IsAllowed(gridId, http.User)) return Results.StatusCode(StatusCodes.Status403Forbidden);
        return await next(context);
    }
}
