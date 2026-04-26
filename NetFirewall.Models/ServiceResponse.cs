namespace NetFirewall.Models;

/// <summary>
/// Standard envelope returned by every backend operation to the UI/API surface.
/// Use the static factories (<see cref="Ok"/>, <see cref="Fail"/>, <see cref="ValidationFailed"/>)
/// rather than constructing instances inline so <see cref="Success"/> stays consistent
/// with the rest of the payload.
/// </summary>
public sealed class ServiceResponse<T>
{
    public bool Success { get; init; }
    public string? Message { get; init; }
    public T? Data { get; init; }

    /// <summary>
    /// Field-level validation errors, keyed by member name (mirrors
    /// <c>ModelStateDictionary</c> so server-side validation results round-trip cleanly).
    /// </summary>
    public IReadOnlyDictionary<string, string[]>? Errors { get; init; }

    /// <summary>Optional correlation id for tying UI failures back to Serilog logs.</summary>
    public string? CorrelationId { get; init; }

    public DateTimeOffset Timestamp { get; init; } = DateTimeOffset.UtcNow;

    public static ServiceResponse<T> Ok(T data, string? message = null) =>
        new() { Success = true, Data = data, Message = message };

    public static ServiceResponse<T> Fail(string message, string? correlationId = null) =>
        new() { Success = false, Message = message, CorrelationId = correlationId };

    public static ServiceResponse<T> ValidationFailed(
        IReadOnlyDictionary<string, string[]> errors,
        string? message = "One or more fields are invalid.") =>
        new() { Success = false, Message = message, Errors = errors };
}
