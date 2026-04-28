using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Abstractions;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.Routing;
using NetFirewall.Models;
using NetFirewall.Web.Filters;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// Action filter that intercepts invalid ModelState on HTMX requests and
/// converts it to a <c>ServiceResponse{T}.ValidationFailed</c> envelope (422)
/// + toast trigger. Pinning the dual contract:
///   - HTMX requests get the JSON envelope so the front end can decorate
///     fields and the toast store renders feedback (project rules #4 + #6).
///   - Non-HTMX (regular form posts to Razor pages) are passed through so the
///     MVC validation pipeline still runs the normal "View(model)" path.
/// </summary>
public class ValidationToServiceResponseFilterTests
{
    private sealed class DummyController : Controller { }

    private static ActionExecutingContext MakeContext(bool isHtmx, ModelStateDictionary? modelState = null)
    {
        var http = new DefaultHttpContext();
        if (isHtmx) http.Request.Headers["HX-Request"] = "true";

        var actionContext = new ActionContext(
            http, new RouteData(), new ControllerActionDescriptor(),
            modelState ?? new ModelStateDictionary());

        // Controller needs its ControllerContext set so AttachToastTrigger can
        // reach controller.Response.Headers without NRE.
        var controller = new DummyController { ControllerContext = new ControllerContext(actionContext) };

        return new ActionExecutingContext(
            actionContext,
            new List<IFilterMetadata>(),
            new Dictionary<string, object?>(),
            controller: controller);
    }

    private static ModelStateDictionary InvalidState(params (string key, string error)[] errors)
    {
        var ms = new ModelStateDictionary();
        foreach (var (k, e) in errors) ms.AddModelError(k, e);
        return ms;
    }

    private static T NextNotInvoked<T>() where T : class => null!;

    // ── Pass-through cases ─────────────────────────────────────────────

    [Fact]
    public void ValidModelState_PassesThrough_NoResultSet()
    {
        var ctx = MakeContext(isHtmx: true);
        // ModelState defaults to valid (no errors).
        new ValidationToServiceResponseFilter().OnActionExecuting(ctx);

        Assert.Null(ctx.Result);
    }

    [Fact]
    public void NonHtmxRequest_InvalidState_PassesThrough()
    {
        // Razor page post — let the standard MVC flow handle it. The controller
        // typically renders View(model) with errors so the page re-shows.
        var ctx = MakeContext(isHtmx: false, modelState: InvalidState(("Username", "required")));

        new ValidationToServiceResponseFilter().OnActionExecuting(ctx);

        Assert.Null(ctx.Result);
        Assert.False(ctx.HttpContext.Response.Headers.ContainsKey("HX-Trigger"));
    }

    // ── HTMX + invalid → 422 envelope ──────────────────────────────────

    [Fact]
    public void HtmxRequest_InvalidState_Returns422_WithEnvelopeShape()
    {
        var ctx = MakeContext(isHtmx: true,
            modelState: InvalidState(("Username", "Username is required."),
                                     ("Password", "Min length 8")));

        new ValidationToServiceResponseFilter().OnActionExecuting(ctx);

        var json = Assert.IsType<JsonResult>(ctx.Result);
        Assert.Equal(422, json.StatusCode);
        var envelope = Assert.IsType<ServiceResponse<object>>(json.Value);
        Assert.False(envelope.Success);
        Assert.NotNull(envelope.Errors);
        Assert.Equal(2, envelope.Errors!.Count);
        Assert.Contains("Username is required.", envelope.Errors["Username"]);
        Assert.Contains("Min length 8", envelope.Errors["Password"]);
    }

    [Fact]
    public void HtmxRequest_InvalidState_AttachesToastTrigger_Warning()
    {
        var ctx = MakeContext(isHtmx: true,
            modelState: InvalidState(("Email", "Invalid format")));

        new ValidationToServiceResponseFilter().OnActionExecuting(ctx);

        var hx = ctx.HttpContext.Response.Headers["HX-Trigger"].ToString();
        Assert.Contains("showToast", hx);
        Assert.Contains("warning", hx);
    }

    [Fact]
    public void EmptyErrorMessage_BecomesGenericInvalidValue()
    {
        // Some validators add an error with no message (e.g. binder errors).
        // The envelope must carry a non-empty string so the UI doesn't render
        // a blank tooltip.
        var ms = new ModelStateDictionary();
        ms.AddModelError("Field", "");

        var ctx = MakeContext(isHtmx: true, modelState: ms);
        new ValidationToServiceResponseFilter().OnActionExecuting(ctx);

        var envelope = (ServiceResponse<object>)((JsonResult)ctx.Result!).Value!;
        Assert.Contains("Invalid value", envelope.Errors!["Field"]);
    }

    [Fact]
    public void MultipleErrorsOnSameField_AllPreservedInEnvelope()
    {
        var ms = new ModelStateDictionary();
        ms.AddModelError("Password", "Too short");
        ms.AddModelError("Password", "Missing digit");
        ms.AddModelError("Password", "Missing symbol");

        var ctx = MakeContext(isHtmx: true, modelState: ms);
        new ValidationToServiceResponseFilter().OnActionExecuting(ctx);

        var envelope = (ServiceResponse<object>)((JsonResult)ctx.Result!).Value!;
        Assert.Equal(3, envelope.Errors!["Password"].Length);
    }

    [Fact]
    public void NonControllerInstance_FallbackPathStillWritesHxTrigger()
    {
        // Razor Pages handlers are PageModel, not Controller. The filter has a
        // fallback that writes HX-Trigger directly via Response.Headers.
        var http = new DefaultHttpContext();
        http.Request.Headers["HX-Request"] = "true";
        var actionContext = new ActionContext(
            http, new RouteData(), new ActionDescriptor(),
            InvalidState(("X", "bad")));
        var ctx = new ActionExecutingContext(
            actionContext, new List<IFilterMetadata>(),
            new Dictionary<string, object?>(),
            controller: new object()); // NOT a Controller

        new ValidationToServiceResponseFilter().OnActionExecuting(ctx);

        Assert.IsType<JsonResult>(ctx.Result);
        var hx = ctx.HttpContext.Response.Headers["HX-Trigger"].ToString();
        Assert.Contains("showToast", hx);
        Assert.Contains("warning", hx);
    }

    [Fact]
    public void OnActionExecuted_IsNoOp_NoExceptions()
    {
        // Filter is action-only (pre-execution). The post-execution hook is
        // intentionally empty — pinning that no logic creeps in.
        var http = new DefaultHttpContext();
        var actionContext = new ActionContext(http, new RouteData(), new ActionDescriptor());
        var executedContext = new ActionExecutedContext(actionContext, new List<IFilterMetadata>(), new DummyController());

        // No throw.
        new ValidationToServiceResponseFilter().OnActionExecuted(executedContext);
    }
}
