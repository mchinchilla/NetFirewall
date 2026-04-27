using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;

namespace NetFirewall.Web.Helpers;

/// <summary>
/// Bridges <see cref="ServiceResponse{T}"/> envelopes to HTMX responses.
/// Adds <c>HX-Trigger</c> headers carrying a <c>showToast</c> event so the
/// shared toast store renders feedback for every request — fulfilling
/// project rule #6 (always show user feedback) without per-action wiring.
/// </summary>
public static class HtmxResultExtensions
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };

    /// <summary>Returns 200 with the given partial fragment, attaching a success toast trigger.</summary>
    public static IActionResult ToHtmxFragment<T>(
        this Controller controller,
        ServiceResponse<T> response,
        string partialName,
        object? model = null)
    {
        AttachToastTrigger(controller, response);

        if (!response.Success)
        {
            // Validation errors — HTMX swap is suppressed and the UI uses the toast/error envelope.
            controller.Response.StatusCode = response.Errors is { Count: > 0 } ? 422 : 400;
            return controller.Json(response);
        }

        return controller.PartialView(partialName, model ?? response.Data);
    }

    /// <summary>For non-fragment endpoints (POST/DELETE that just need toast feedback).</summary>
    public static IActionResult ToHtmxResponse<T>(this Controller controller, ServiceResponse<T> response)
    {
        AttachToastTrigger(controller, response);

        if (!response.Success)
        {
            controller.Response.StatusCode = response.Errors is { Count: > 0 } ? 422 : 400;
        }

        return controller.Json(response);
    }

    /// <summary>
    /// Attaches an <c>HX-Trigger</c> header that fires a <c>showToast</c> event in the browser.
    /// Skips when the response has no message AND no errors (silent success on a partial swap).
    /// Merges into any existing HX-Trigger payload so callers that have already
    /// emitted a custom event (e.g. <c>elevationGranted</c>) don't get clobbered.
    /// </summary>
    public static void AttachToastTrigger<T>(this Controller controller, ServiceResponse<T> response)
    {
        if (response.Success && string.IsNullOrEmpty(response.Message)) return;

        var level = !response.Success
            ? (response.Errors is { Count: > 0 } ? "warning" : "error")
            : "success";

        var message = response.Message
                      ?? (response.Errors is { Count: > 0 }
                          ? string.Join(", ", response.Errors.Select(kv => $"{kv.Key}: {string.Join(", ", kv.Value)}"))
                          : string.Empty);

        controller.AttachHxEvent("showToast", new { level, message });
    }

    /// <summary>
    /// Adds a single named event to the response's <c>HX-Trigger</c> header,
    /// merging with any events already attached to it. Without merging, the
    /// last writer wins and earlier events vanish silently — that bit
    /// <c>elevationGranted</c> for a release: the toast trigger overwrote the
    /// "replay original action" event, so step-up TOTP looked like it worked
    /// but never re-fired the user's original button click.
    /// </summary>
    public static void AttachHxEvent(this Controller controller, string eventName, object payload)
    {
        var existing = controller.Response.Headers["HX-Trigger"].ToString();
        Dictionary<string, object> events;
        if (string.IsNullOrEmpty(existing))
        {
            events = new Dictionary<string, object>();
        }
        else
        {
            try
            {
                events = JsonSerializer.Deserialize<Dictionary<string, object>>(existing, JsonOpts)
                         ?? new Dictionary<string, object>();
            }
            catch (JsonException)
            {
                // Existing header isn't a JSON object — start fresh rather than
                // crash the response. Caller retains the new event; the legacy
                // value is dropped.
                events = new Dictionary<string, object>();
            }
        }
        events[eventName] = payload;
        controller.Response.Headers["HX-Trigger"] = JsonSerializer.Serialize(events, JsonOpts);
    }

    /// <summary>True when the current request was issued by HTMX.</summary>
    public static bool IsHtmxRequest(this HttpRequest request) =>
        request.Headers.ContainsKey("HX-Request");
}
