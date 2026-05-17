using Microsoft.AspNetCore.Mvc.Filters;

namespace NetFirewall.Daemon.Auth;

/// <summary>
/// Marker attribute that documents an endpoint as eligible for the
/// root-peer bypass installed pipeline-wide by
/// <see cref="RootPeerBypassMiddleware"/>. No-op as a filter — left in
/// the metadata for grep-ability so future maintainers see at a glance
/// "this endpoint accepts root-peer instead of session token". The
/// actual bypass happens in the middleware (before UseAuthorization)
/// because MVC filters run too late to mutate <c>HttpContext.User</c>.
/// </summary>
[AttributeUsage(AttributeTargets.Method | AttributeTargets.Class)]
public sealed class DaemonAllowRootPeerAttribute : Attribute, IAuthorizationFilter
{
    public void OnAuthorization(AuthorizationFilterContext context)
    {
        // Intentionally empty — bypass is performed by RootPeerBypassMiddleware
        // which runs in the request pipeline before this filter.
    }
}
