using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using NetFirewall.Models;
using NetFirewall.Web.Helpers;

namespace NetFirewall.Web.Filters;

/// <summary>
/// Intercepts invalid <see cref="Microsoft.AspNetCore.Mvc.ModelBinding.ModelStateDictionary"/>
/// on HTMX-originated requests and converts it into a
/// <see cref="ServiceResponse{T}"/> with field-level errors plus an
/// <c>HX-Trigger</c> warning toast. Honors project rules #4 (dual validation)
/// and #6 (always show feedback) automatically — controllers stop having to
/// hand-roll <c>if (!ModelState.IsValid)</c> branches for HTMX endpoints.
///
/// Non-HTMX requests are left untouched so traditional Razor pages keep their
/// usual MVC validation flow.
/// </summary>
public sealed class ValidationToServiceResponseFilter : IActionFilter
{
    public void OnActionExecuting(ActionExecutingContext context)
    {
        if (context.ModelState.IsValid) return;
        if (!context.HttpContext.Request.IsHtmxRequest()) return;

        var errors = context.ModelState
            .Where(kv => kv.Value is { Errors.Count: > 0 })
            .ToDictionary(
                kv => kv.Key,
                kv => kv.Value!.Errors.Select(e => string.IsNullOrEmpty(e.ErrorMessage) ? "Invalid value" : e.ErrorMessage).ToArray()
            );

        var envelope = ServiceResponse<object>.ValidationFailed(errors);

        var controller = context.Controller as Controller;
        if (controller != null)
        {
            controller.AttachToastTrigger(envelope);
        }
        else
        {
            // Fallback: plain HX-Trigger without controller convenience.
            context.HttpContext.Response.Headers["HX-Trigger"] =
                System.Text.Json.JsonSerializer.Serialize(new { showToast = new { level = "warning", message = envelope.Message ?? "Validation failed" } });
        }

        context.Result = new JsonResult(envelope) { StatusCode = 422 };
    }

    public void OnActionExecuted(ActionExecutedContext context) { }
}
