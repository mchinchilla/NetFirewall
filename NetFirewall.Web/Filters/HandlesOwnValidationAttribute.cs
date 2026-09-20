namespace NetFirewall.Web.Filters;

/// <summary>
/// Opt out of <see cref="ValidationToServiceResponseFilter"/> short-circuiting.
///
/// The filter turns an invalid ModelState into a 422 + toast before the action
/// runs, which is right for most endpoints but wrong for a form: the operator
/// gets a message with no idea which field it refers to. An action marked with
/// this attribute is entered even when ModelState is invalid, so it can
/// re-render its own partial — with whatever ViewBag data that partial needs —
/// and let _FormField paint the errors next to the offending inputs.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
public sealed class HandlesOwnValidationAttribute : Attribute;
