using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using NetFirewall.Web.Controllers;
using Xunit;

namespace NetFirewall.Tests.Web;

/// <summary>
/// Lint: every MVC controller states who may use it. The global AuthorizeFilter only
/// demands a session, so a controller without a role gate is open to Viewers — that is
/// how Network → Interfaces and WAN failover once let a read-only account re-address the
/// firewall and pin its uplink. A new controller must either carry a class-level
/// <c>[Authorize(Roles = …)]</c> / <c>[AllowAnonymous]</c>, or be listed below with the
/// reason it is open to every signed-in user.
/// </summary>
public class ControllerRoleGateTests
{
    /// <summary>Open to any signed-in user (or anonymous where marked) on purpose.</summary>
    private static readonly Dictionary<Type, string> AnyUser = new()
    {
        [typeof(AccountController)]     = "the caller's own profile, TOTP, recovery codes and sessions — every role",
        [typeof(AuthController)]        = "login / TOTP / elevation — must work before and without a role",
        [typeof(HomeController)]        = "dashboard, read-only, every role",
        [typeof(SearchController)]      = "global search, read-only, every role",
        [typeof(PreferencesController)] = "per-browser appearance cookie, changes nothing on the box",
        [typeof(StaticRoutesController)] = "list is read-only for viewers; every mutation is role-gated per action (checked below)",
    };

    private static IEnumerable<Type> Controllers() =>
        typeof(HomeController).Assembly.GetTypes()
            .Where(t => t is { IsClass: true, IsAbstract: false } && typeof(ControllerBase).IsAssignableFrom(t));

    private static bool HasRoles(MemberInfo m) =>
        m.GetCustomAttributes<AuthorizeAttribute>(inherit: true).Any(a => !string.IsNullOrWhiteSpace(a.Roles));

    private static bool IsAnonymous(MemberInfo m) =>
        m.GetCustomAttributes<AllowAnonymousAttribute>(inherit: true).Any();

    [Fact]
    public void EveryController_HasARoleGate_OrAStatedReason()
    {
        var ungated = Controllers()
            .Where(t => !HasRoles(t) && !IsAnonymous(t) && !AnyUser.ContainsKey(t))
            .Select(t => t.Name)
            .ToList();

        Assert.True(ungated.Count == 0,
            "Controllers with no role gate (add [Authorize(Roles = …)] or list them in AnyUser with a reason): "
            + string.Join(", ", ungated));
    }

    [Fact]
    public void NetworkAndWanFailover_AreAdminOrOperatorOnly()
    {
        foreach (var t in new[] { typeof(NetworkController), typeof(WanFailoverController) })
        {
            var roles = t.GetCustomAttributes<AuthorizeAttribute>().Select(a => a.Roles ?? "").ToList();
            Assert.Contains(roles, r => r.Contains("admin") && r.Contains("operator") && !r.Contains("viewer"));
        }
    }

    [Fact]
    public void StaticRoutes_EveryMutation_IsRoleGated()
    {
        var open = typeof(StaticRoutesController)
            .GetMethods(BindingFlags.Instance | BindingFlags.Public | BindingFlags.DeclaredOnly)
            .Where(m => m.GetCustomAttributes<HttpMethodAttribute>().Any(h => h.HttpMethods.Any(x => x != "GET")))
            .Where(m => !HasRoles(m))
            .Select(m => m.Name)
            .ToList();

        Assert.True(open.Count == 0, "StaticRoutes mutations without a role gate: " + string.Join(", ", open));
    }
}
