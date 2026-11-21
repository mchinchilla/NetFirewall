using System.Security.Claims;
using NetFirewall.Models.Auth;

namespace NetFirewall.Web.Helpers;

/// <summary>Role questions the views and controllers ask, in one place.</summary>
public static class UserRoleExtensions
{
    /// <summary>Admin or Operator — may change configuration (Viewer is read-only).</summary>
    public static bool CanOperate(this ClaimsPrincipal user) =>
        user.IsInRole(UserRoles.Admin) || user.IsInRole(UserRoles.Operator);
}
