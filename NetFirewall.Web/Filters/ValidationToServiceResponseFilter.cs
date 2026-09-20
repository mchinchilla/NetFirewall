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

        // The action re-renders its own form with inline errors — don't pre-empt it.
        if (context.ActionDescriptor.EndpointMetadata.OfType<HandlesOwnValidationAttribute>().Any()) return;

        var errors = context.ModelState
            .Where(kv => kv.Value is { Errors.Count: > 0 })
            .ToDictionary(
                kv => kv.Key,
                kv => kv.Value!.Errors.Select(e => string.IsNullOrEmpty(e.ErrorMessage) ? "Invalid value" : e.ErrorMessage).ToArray()
            );

        // "One or more fields are invalid" tells the operator nothing when the form
        // has a dozen inputs. Name the fields and quote the reasons in the toast.
        var summary = string.Join(" ", errors
            .SelectMany(kv => kv.Value.Select(msg => FieldLabel(kv.Key) is { Length: > 0 } f ? $"{f}: {msg}" : msg))
            .Take(4));
        if (summary.Length > 400) summary = summary[..400] + "…";

        var envelope = ServiceResponse<object>.ValidationFailed(
            errors, string.IsNullOrWhiteSpace(summary) ? null : summary);

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

    /// <summary>
    /// ModelState keys are property paths (<c>Value</c>, <c>Lans[0].EnableDhcp</c>).
    /// Show the leaf, spaced out, so the toast reads like the label above the input.
    /// </summary>
    internal static string FieldLabel(string key)
    {
        if (string.IsNullOrWhiteSpace(key)) return string.Empty;
        var leaf = key[(key.LastIndexOf('.') + 1)..].TrimEnd(']');
        var bracket = leaf.IndexOf('[');
        if (bracket > 0) leaf = leaf[..bracket];

        var spaced = System.Text.RegularExpressions.Regex.Replace(leaf, "(?<!^)([A-Z])", " $1");
        return spaced.Length == 0 ? string.Empty : char.ToUpperInvariant(spaced[0]) + spaced[1..];
    }
}
