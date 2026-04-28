using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using NetFirewall.Models;
using NetFirewall.Web.Helpers;
using Xunit;

namespace NetFirewall.Tests.WebAuth;

/// <summary>
/// Direct coverage for the HTMX response helper. Two production bugs lived
/// here before the refactor:
///   - <c>AttachToastTrigger</c> overwrote any prior <c>HX-Trigger</c> header,
///     making it impossible to combine a toast with a panel-refresh event.
///   - Controllers had to know that order; <c>AttachHxEvent</c> now merges
///     properly. These tests pin the merge semantics so a future "simpler"
///     refactor can't reintroduce the clobber.
/// </summary>
public class HtmxResultExtensionsTests
{
    private sealed class TestController : Controller { }

    private static TestController MakeController()
    {
        var ctx = new DefaultHttpContext();
        return new TestController
        {
            ControllerContext = new ControllerContext { HttpContext = ctx }
        };
    }

    private static Dictionary<string, JsonElement> ParseTrigger(string headerValue) =>
        JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(headerValue)
        ?? new Dictionary<string, JsonElement>();

    // ── IsHtmxRequest ──────────────────────────────────────────────────

    [Fact]
    public void IsHtmxRequest_WithHxRequestHeader_ReturnsTrue()
    {
        var ctx = new DefaultHttpContext();
        ctx.Request.Headers["HX-Request"] = "true";
        Assert.True(ctx.Request.IsHtmxRequest());
    }

    [Fact]
    public void IsHtmxRequest_WithoutHeader_ReturnsFalse()
    {
        Assert.False(new DefaultHttpContext().Request.IsHtmxRequest());
    }

    // ── AttachToastTrigger ─────────────────────────────────────────────

    [Fact]
    public void AttachToastTrigger_SuccessWithMessage_EmitsSuccessToast()
    {
        var c = MakeController();
        c.AttachToastTrigger(ServiceResponse<string>.Ok("data", "Saved!"));

        var trigger = ParseTrigger(c.Response.Headers["HX-Trigger"].ToString());
        Assert.True(trigger.ContainsKey("showToast"));
        var toast = trigger["showToast"];
        Assert.Equal("success", toast.GetProperty("level").GetString());
        Assert.Equal("Saved!", toast.GetProperty("message").GetString());
    }

    [Fact]
    public void AttachToastTrigger_SuccessNoMessage_NoHeaderEmitted()
    {
        // Silent success on a partial swap — nothing to toast about.
        var c = MakeController();
        c.AttachToastTrigger(ServiceResponse<string>.Ok("data"));

        Assert.False(c.Response.Headers.ContainsKey("HX-Trigger"));
    }

    [Fact]
    public void AttachToastTrigger_FailWithMessage_EmitsErrorToast()
    {
        var c = MakeController();
        c.AttachToastTrigger(ServiceResponse<string>.Fail("DB unreachable"));

        var trigger = ParseTrigger(c.Response.Headers["HX-Trigger"].ToString());
        var toast = trigger["showToast"];
        Assert.Equal("error", toast.GetProperty("level").GetString());
        Assert.Equal("DB unreachable", toast.GetProperty("message").GetString());
    }

    [Fact]
    public void AttachToastTrigger_ValidationFailure_EmitsWarningWithJoinedFieldErrors()
    {
        // Validation envelope with field-level errors → warning toast that
        // summarises them. Keeps users informed even when the form-level
        // error decoration is hidden by an HTMX swap.
        var envelope = ServiceResponse<object>.ValidationFailed(new Dictionary<string, string[]>
        {
            ["Username"] = new[] { "required" },
            ["Email"]    = new[] { "invalid format" }
        });
        var c = MakeController();
        c.AttachToastTrigger(envelope);

        var trigger = ParseTrigger(c.Response.Headers["HX-Trigger"].ToString());
        var toast = trigger["showToast"];
        Assert.Equal("warning", toast.GetProperty("level").GetString());
        // Either the envelope's own message OR the joined errors — pin that
        // SOMETHING explanatory landed there.
        var msg = toast.GetProperty("message").GetString();
        Assert.False(string.IsNullOrEmpty(msg));
    }

    // ── AttachHxEvent: merge semantics (the regression-pin) ────────────

    [Fact]
    public void AttachHxEvent_WithoutPriorHeader_StartsFreshObject()
    {
        var c = MakeController();
        c.AttachHxEvent("firewallApplied", new { });

        var trigger = ParseTrigger(c.Response.Headers["HX-Trigger"].ToString());
        Assert.Single(trigger);
        Assert.True(trigger.ContainsKey("firewallApplied"));
    }

    [Fact]
    public void AttachHxEvent_WithPriorJsonHeader_MergesNewKey_PreservesOld()
    {
        // The bug class this guards: the old AttachToastTrigger overwrote any
        // earlier HX-Trigger value. Now both must coexist.
        var c = MakeController();
        c.AttachToastTrigger(ServiceResponse<string>.Ok("d", "Done"));    // adds showToast
        c.AttachHxEvent("firewallApplied", new { });                     // must NOT clobber

        var trigger = ParseTrigger(c.Response.Headers["HX-Trigger"].ToString());
        Assert.True(trigger.ContainsKey("showToast"));
        Assert.True(trigger.ContainsKey("firewallApplied"));
    }

    [Fact]
    public void AttachHxEvent_TwoCustomEvents_BothPresent()
    {
        var c = MakeController();
        c.AttachHxEvent("eventA", new { id = 1 });
        c.AttachHxEvent("eventB", new { name = "x" });

        var trigger = ParseTrigger(c.Response.Headers["HX-Trigger"].ToString());
        Assert.True(trigger.ContainsKey("eventA"));
        Assert.True(trigger.ContainsKey("eventB"));
    }

    [Fact]
    public void AttachHxEvent_SameKeyTwice_LastOneWins()
    {
        // Within a single event name, last write wins (intentional override).
        var c = MakeController();
        c.AttachHxEvent("update", new { value = "first" });
        c.AttachHxEvent("update", new { value = "second" });

        var trigger = ParseTrigger(c.Response.Headers["HX-Trigger"].ToString());
        Assert.Equal("second", trigger["update"].GetProperty("value").GetString());
    }

    [Fact]
    public void AttachHxEvent_PriorHeaderIsRawString_DoesNotCrash_StartsFresh()
    {
        // Older code wrote raw event names as the header value
        // (`Response.Headers["HX-Trigger"] = "firewallApplied";`). If anyone
        // still does that, AttachHxEvent must NOT throw — the raw string isn't
        // valid JSON, so the merge falls back to a fresh dict (the legacy
        // value is dropped, which is the trade-off we accept).
        var c = MakeController();
        c.Response.Headers["HX-Trigger"] = "raw-event-name";

        c.AttachHxEvent("firewallApplied", new { });

        var trigger = ParseTrigger(c.Response.Headers["HX-Trigger"].ToString());
        Assert.True(trigger.ContainsKey("firewallApplied"));
        Assert.False(trigger.ContainsKey("raw-event-name"));
    }

    // ── ToHtmxResponse ─────────────────────────────────────────────────

    [Fact]
    public void ToHtmxResponse_Success_Returns200_JsonEnvelope()
    {
        var c = MakeController();
        var result = c.ToHtmxResponse(ServiceResponse<string>.Ok("data", "ok"));

        var json = Assert.IsType<JsonResult>(result);
        Assert.IsType<ServiceResponse<string>>(json.Value);
        // Default status (200) — JsonResult.StatusCode is null until set.
        Assert.Null(json.StatusCode);
    }

    [Fact]
    public void ToHtmxResponse_FailWithoutErrors_Sets400()
    {
        var c = MakeController();
        var result = c.ToHtmxResponse(ServiceResponse<string>.Fail("boom"));

        Assert.IsType<JsonResult>(result);
        Assert.Equal(400, c.Response.StatusCode);
    }

    [Fact]
    public void ToHtmxResponse_ValidationFailure_Sets422()
    {
        // Field-level errors → 422 Unprocessable Entity (semantic distinction
        // from a generic 400). HTMX response handlers typically branch on
        // 422 to decorate fields vs 400 to show a generic banner.
        var c = MakeController();
        var envelope = ServiceResponse<string>.ValidationFailed(
            new Dictionary<string, string[]> { ["Field"] = new[] { "bad" } });

        c.ToHtmxResponse(envelope);

        Assert.Equal(422, c.Response.StatusCode);
    }

    // ── ToHtmxFragment ─────────────────────────────────────────────────

    [Fact]
    public void ToHtmxFragment_Success_ReturnsPartialView()
    {
        var c = MakeController();
        var result = c.ToHtmxFragment(ServiceResponse<string>.Ok("payload"), "_MyPartial");

        var partial = Assert.IsType<PartialViewResult>(result);
        Assert.Equal("_MyPartial", partial.ViewName);
        Assert.Equal("payload", partial.Model);
    }

    [Fact]
    public void ToHtmxFragment_ExplicitModelOverride_UsedInsteadOfEnvelopeData()
    {
        var c = MakeController();
        var explicitModel = new { kind = "view-model" };

        var result = c.ToHtmxFragment(
            ServiceResponse<string>.Ok("envelope-data"),
            "_MyPartial",
            model: explicitModel);

        var partial = Assert.IsType<PartialViewResult>(result);
        Assert.Same(explicitModel, partial.Model);
    }

    [Fact]
    public void ToHtmxFragment_Fail_SuppressesSwap_ReturnsJson400()
    {
        var c = MakeController();
        var result = c.ToHtmxFragment(ServiceResponse<string>.Fail("boom"), "_X");

        Assert.IsType<JsonResult>(result);
        Assert.Equal(400, c.Response.StatusCode);
    }

    [Fact]
    public void ToHtmxFragment_ValidationFailure_SuppressesSwap_Returns422()
    {
        var c = MakeController();
        var envelope = ServiceResponse<string>.ValidationFailed(
            new Dictionary<string, string[]> { ["X"] = new[] { "y" } });

        c.ToHtmxFragment(envelope, "_X");

        Assert.Equal(422, c.Response.StatusCode);
    }
}
